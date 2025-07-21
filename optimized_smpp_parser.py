import pyshark
import pandas as pd
import struct
from datetime import datetime
import os
import gc
import logging
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from typing import Dict, List, Optional, Tuple, Any

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Set tshark path if needed
pyshark.tshark.tshark.get_tshark_path = lambda: '/usr/bin/tshark'

class SMPPParser:
    def __init__(self, output_dir: str = "/auraOutputs"):
        self.output_dir = output_dir
        self.fmt = '%d/%m/%y %H:%M:%S'
        
        # Thread-safe data structures
        self.lock = threading.Lock()
        self.submit_sm = {}
        self.submit_sm_resp = {}
        self.deliver_sm = {}
        self.deliver_sm_resp = {}
        self.msgid_to_deliver = defaultdict(list)
        
        self.counters = {
            'submit_sm': 0,
            'submit_sm_resp': 0,
            'deliver_sm': 0,
            'deliver_sm_resp': 0,
            'full_chains': 0,
            'partial_chains': 0,
            'submit_resp_matched': 0,
            'resp_deliver_matched': 0,
            'deliver_resp_matched': 0
        }
        
        self.delta_submit_resp = []
        self.delta_resp_deliver = []
        self.delta_deliver_resp = []
    
    def clean_payload(self, raw_payload) -> Optional[str]:
        """Clean and validate payload data"""
        try:
            if isinstance(raw_payload, list):
                raw_payload = ''.join(raw_payload)
            
            # Use translate for faster character removal
            cleaned = raw_payload.translate(str.maketrans('', '', ': \t\n\r'))
            
            # Quick validation - check if it's valid hex
            if len(cleaned) % 2 != 0:
                return None
                
            # Test a small portion first to avoid full conversion
            bytes.fromhex(cleaned[:16])  # Test first 8 bytes
            return cleaned
        except (ValueError, TypeError):
            return None
    
    def extract_pdus_from_payload(self, payload_hex: str) -> List[bytes]:
        """Extract PDUs from hex payload with better error handling"""
        pdus = []
        try:
            payload = bytes.fromhex(payload_hex)
        except ValueError:
            return pdus
        
        i = 0
        max_iterations = 100  # Prevent infinite loops
        iterations = 0
        
        while i + 4 <= len(payload) and iterations < max_iterations:
            try:
                pdu_len = struct.unpack('!I', payload[i:i+4])[0]
                
                # Sanity checks
                if pdu_len < 16 or pdu_len > 65536 or i + pdu_len > len(payload):
                    break
                    
                pdus.append(payload[i:i+pdu_len])
                i += pdu_len
                iterations += 1
            except (struct.error, MemoryError):
                break
                
        return pdus
    
    def parse_single_pdu(self, pdu_bytes: bytes, pkt_info: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """Parse a single PDU with optimized message ID extraction"""
        try:
            if len(pdu_bytes) < 16:
                return None
            
            # Use struct.unpack_from for better performance
            cmd = struct.unpack_from('!I', pdu_bytes, 4)[0]
            seq = struct.unpack_from('!I', pdu_bytes, 12)[0]
            
            cmd_hex = f"0x{cmd:08x}"
            seq_str = str(seq)
            msg_id = None
            
            # Optimize message ID extraction
            if cmd == 0x00000005:  # deliver_sm
                msg_id = self._extract_deliver_sm_msg_id(pdu_bytes)
            elif cmd == 0x80000004:  # submit_sm_resp
                msg_id = self._extract_submit_sm_resp_msg_id(pdu_bytes)
            
            return {
                'command_id': cmd_hex,
                'sequence_number': seq_str,
                'message_id': msg_id,
                'src_ip': pkt_info['src_ip'],
                'src_port': pkt_info['src_port'],
                'dst_ip': pkt_info['dst_ip'],
                'dst_port': pkt_info['dst_port'],
                'timestamp': pkt_info['timestamp']
            }
        except (struct.error, IndexError):
            return None
    
    def _extract_deliver_sm_msg_id(self, pdu_bytes: bytes) -> Optional[str]:
        """Optimized deliver_sm message ID extraction"""
        try:
            # Look for 'id:' pattern in bytes directly
            pdu_view = memoryview(pdu_bytes)
            id_pattern = b'id:'
            sub_pattern = b'sub'
            
            start_idx = pdu_bytes.find(id_pattern)
            if start_idx == -1:
                return None
                
            end_idx = pdu_bytes.find(sub_pattern, start_idx)
            if end_idx == -1 or end_idx <= start_idx + 3:
                return None
            
            msg_id_bytes = pdu_bytes[start_idx + 3:end_idx]
            return msg_id_bytes.decode('utf-8', errors='ignore').strip().lower()
        except (UnicodeDecodeError, ValueError):
            return None
    
    def _extract_submit_sm_resp_msg_id(self, pdu_bytes: bytes) -> Optional[str]:
        """Optimized submit_sm_resp message ID extraction"""
        try:
            if len(pdu_bytes) <= 16:
                return None
                
            # Find first null terminator
            null_idx = pdu_bytes.find(b'\x00', 16)
            if null_idx == -1:
                null_idx = len(pdu_bytes)
                
            msg_id_bytes = pdu_bytes[16:null_idx]
            return msg_id_bytes.decode('utf-8', errors='ignore').strip().lower()
        except (UnicodeDecodeError, ValueError):
            return None
    
    def parse_pcap_file(self, pcap_file: str, retry_count: int = 3) -> bool:
        """Parse a single PCAP file with retry mechanism"""
        logger.info(f"Parsing {pcap_file}")
        local_records = []
        
        for attempt in range(retry_count):
            try:
                # Use more conservative settings to avoid TShark crashes
                cap = pyshark.FileCapture(
                    pcap_file, 
                    display_filter="smpp", 
                    use_json=True, 
                    include_raw=True, 
                    keep_packets=False,
                    # Remove custom parameters that might cause issues
                )
                
                # Set debug mode if this is a retry
                if attempt > 0:
                    cap.set_debug()
                    logger.info(f"Retry attempt {attempt + 1} for {pcap_file} with debug mode")
                
                batch_size = 500  # Reduced batch size for stability
                batch_count = 0
                packet_count = 0
                
                for pkt in cap:
                    try:
                        packet_count += 1
                        
                        # Skip packets without TCP payload
                        if not hasattr(pkt, 'tcp'):
                            continue
                            
                        raw_payload = getattr(pkt.tcp, 'segment_data', None) or getattr(pkt.tcp, 'payload', None)
                        if not raw_payload:
                            continue
                        
                        payload_hex = self.clean_payload(raw_payload)
                        if not payload_hex:
                            continue
                        
                        # Pre-calculate timestamp to avoid repeated conversions
                        timestamp = datetime.fromtimestamp(float(pkt.sniff_timestamp)).strftime(self.fmt)
                        
                        pkt_info = {
                            'src_ip': pkt.ip.src,
                            'dst_ip': pkt.ip.dst,
                            'src_port': pkt.tcp.srcport,
                            'dst_port': pkt.tcp.dstport,
                            'timestamp': timestamp
                        }
                        
                        pdus = self.extract_pdus_from_payload(payload_hex)
                        for pdu in pdus:
                            rec = self.parse_single_pdu(pdu, pkt_info)
                            if rec:
                                local_records.append(rec)
                        
                        # Process in smaller batches to avoid memory buildup
                        batch_count += 1
                        if batch_count >= batch_size:
                            self._process_records_batch(local_records)
                            local_records.clear()
                            batch_count = 0
                            gc.collect()  # Force garbage collection
                            
                    except Exception as e:
                        logger.warning(f"Error parsing packet {packet_count} in {pcap_file}: {e}")
                        continue
                
                # Process remaining records
                if local_records:
                    self._process_records_batch(local_records)
                
                cap.close()
                logger.info(f"Successfully processed {pcap_file} ({packet_count} packets)")
                return True
                
            except Exception as e:
                logger.error(f"Attempt {attempt + 1} failed for {pcap_file}: {e}")
                if attempt < retry_count - 1:
                    logger.info(f"Retrying {pcap_file} in 2 seconds...")
                    import time
                    time.sleep(2)  # Wait before retry
                else:
                    logger.error(f"All retry attempts failed for {pcap_file}")
                    return False
        
        return False
    
    def _process_records_batch(self, records: List[Dict[str, Any]]):
        """Process a batch of records in a thread-safe manner"""
        with self.lock:
            for rec in records:
                key = (rec['sequence_number'], rec['src_ip'], rec['src_port'], rec['dst_ip'], rec['dst_port'])
                cmd = rec['command_id']
                mid = rec['message_id']
                
                if cmd == '0x00000004':
                    self.submit_sm[key] = rec
                    self.counters['submit_sm'] += 1
                elif cmd == '0x80000004':
                    self.submit_sm_resp[key] = rec
                    self.counters['submit_sm_resp'] += 1
                elif cmd == '0x00000005':
                    self.deliver_sm[key] = rec
                    if mid:
                        self.msgid_to_deliver[mid].append((key, rec))
                    self.counters['deliver_sm'] += 1
                elif cmd == '0x80000005':
                    self.deliver_sm_resp[key] = rec
                    self.counters['deliver_sm_resp'] += 1
    
    def calculate_time_delta(self, time1: str, time2: str) -> Optional[float]:
        """Calculate time delta between two timestamps"""
        try:
            dt1 = datetime.strptime(time1, self.fmt)
            dt2 = datetime.strptime(time2, self.fmt)
            return (dt2 - dt1).total_seconds()
        except (ValueError, TypeError):
            return None
    
    def build_chains(self) -> List[Dict[str, Any]]:
        """Build message chains with optimized matching"""
        chain_records = []
        
        logger.info("Building message chains...")
        
        for sub_key, sub in self.submit_sm.items():
            rev_key = (sub_key[0], sub_key[3], sub_key[4], sub_key[1], sub_key[2])
            resp = self.submit_sm_resp.get(rev_key)
            
            if resp:
                self.counters['submit_resp_matched'] += 1
            
            msg_id = resp['message_id'] if resp else None
            drec = None
            dkey = None
            
            if msg_id and msg_id in self.msgid_to_deliver:
                # Get first matching deliver record
                for dk, v in self.msgid_to_deliver[msg_id]:
                    dkey = dk
                    drec = v
                    self.counters['resp_deliver_matched'] += 1
                    break
            
            dresp = None
            if dkey:
                rev_dkey = (dkey[0], dkey[3], dkey[4], dkey[1], dkey[2])
                dresp = self.deliver_sm_resp.get(rev_dkey)
                if dresp:
                    self.counters['deliver_resp_matched'] += 1
            
            # Build row data
            row = self._build_chain_row(sub_key, sub, resp, msg_id, dkey, drec, dresp)
            
            # Update counters and deltas
            if resp and drec and dresp:
                self.counters['full_chains'] += 1
            else:
                self.counters['partial_chains'] += 1
            
            # Calculate time deltas
            self._calculate_deltas(sub, resp, drec, dresp)
            
            chain_records.append(row)
        
        return chain_records
    
    def _build_chain_row(self, sub_key, sub, resp, msg_id, dkey, drec, dresp) -> Dict[str, Any]:
        """Build a single chain row"""
        return {
            'submit_sm_seq': sub_key[0],
            'submit_sm_time': sub['timestamp'],
            'submit_src': f"{sub['src_ip']}:{sub['src_port']}",
            'submit_dst': f"{sub['dst_ip']}:{sub['dst_port']}",
            'submit_resp_seq': resp['sequence_number'] if resp else None,
            'submit_resp_time': resp['timestamp'] if resp else None,
            'submit_resp_src': f"{resp['src_ip']}:{resp['src_port']}" if resp else None,
            'submit_resp_dst': f"{resp['dst_ip']}:{resp['dst_port']}" if resp else None,
            'message_id': msg_id,
            'deliver_seq': dkey[0] if dkey else None,
            'deliver_time': drec['timestamp'] if drec else None,
            'deliver_src': f"{drec['src_ip']}:{drec['src_port']}" if drec else None,
            'deliver_dst': f"{drec['dst_ip']}:{drec['dst_port']}" if drec else None,
            'deliver_resp_seq': dresp['sequence_number'] if dresp else None,
            'deliver_resp_time': dresp['timestamp'] if dresp else None,
            'deliver_resp_src': f"{dresp['src_ip']}:{dresp['src_port']}" if dresp else None,
            'deliver_resp_dst': f"{dresp['dst_ip']}:{dresp['dst_port']}" if dresp else None
        }
    
    def _calculate_deltas(self, sub, resp, drec, dresp):
        """Calculate time deltas between message types"""
        if resp:
            delta = self.calculate_time_delta(sub['timestamp'], resp['timestamp'])
            if delta is not None:
                self.delta_submit_resp.append(delta)
        
        if resp and drec:
            delta = self.calculate_time_delta(resp['timestamp'], drec['timestamp'])
            if delta is not None:
                self.delta_resp_deliver.append(delta)
        
        if drec and dresp:
            delta = self.calculate_time_delta(drec['timestamp'], dresp['timestamp'])
            if delta is not None:
                self.delta_deliver_resp.append(delta)
    
    def generate_output_data(self, chain_records: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Generate all output datasets"""
        logger.info("Generating output datasets...")
        
        # Categorize chains
        matched_chains = []
        submit_chain_no_deliver = []
        
        for row in chain_records:
            if row['submit_resp_seq'] and row['deliver_seq'] and row['deliver_resp_seq']:
                matched_chains.append(row)
            elif row['submit_resp_seq'] and not row['deliver_seq']:
                submit_chain_no_deliver.append(row)
        
        # Generate other datasets
        submit_resp_no_submit = self._get_submit_resp_no_submit()
        deliver_pair_no_submit_resp = self._get_deliver_pair_no_submit_resp()
        deliver_no_response = self._get_deliver_no_response()
        
        return {
            'matched_full_chains': matched_chains,
            'submit_sm_resp_without_submit': submit_resp_no_submit,
            'deliver_chain_without_submit_resp': deliver_pair_no_submit_resp,
            'submit_chain_without_delivery': submit_chain_no_deliver,
            'deliver_sm_without_response': deliver_no_response
        }
    
    def _get_submit_resp_no_submit(self) -> List[Dict[str, Any]]:
        """Get submit responses without corresponding submits"""
        result = []
        for key, resp in self.submit_sm_resp.items():
            rev_key = (key[0], key[3], key[4], key[1], key[2])
            if rev_key not in self.submit_sm:
                result.append({
                    'sequence_number': resp['sequence_number'],
                    'timestamp': resp['timestamp'],
                    'src': f"{resp['src_ip']}:{resp['src_port']}",
                    'dst': f"{resp['dst_ip']}:{resp['dst_port']}"
                })
        return result
    
    def _get_deliver_pair_no_submit_resp(self) -> List[Dict[str, Any]]:
        """Get deliver pairs without corresponding submit responses"""
        result = []
        seen_msg_ids = {resp['message_id'] for resp in self.submit_sm_resp.values() if resp['message_id']}
        
        for dkey, dsm in self.deliver_sm.items():
            rev_dkey = (dkey[0], dkey[3], dkey[4], dkey[1], dkey[2])
            dresp = self.deliver_sm_resp.get(rev_dkey)
            
            if dresp and dsm['message_id'] and dsm['message_id'] not in seen_msg_ids:
                result.append({
                    'deliver_seq': dkey[0],
                    'deliver_time': dsm['timestamp'],
                    'deliver_src': f"{dsm['src_ip']}:{dsm['src_port']}",
                    'deliver_dst': f"{dsm['dst_ip']}:{dsm['dst_port']}",
                    'deliver_resp_seq': dresp['sequence_number'],
                    'deliver_resp_time': dresp['timestamp'],
                    'deliver_resp_src': f"{dresp['src_ip']}:{dresp['src_port']}",
                    'deliver_resp_dst': f"{dresp['dst_ip']}:{dresp['dst_port']}",
                    'message_id': dsm['message_id']
                })
        return result
    
    def _get_deliver_no_response(self) -> List[Dict[str, Any]]:
        """Get deliver messages without responses"""
        result = []
        for dkey, dsm in self.deliver_sm.items():
            rev_dkey = (dkey[0], dkey[3], dkey[4], dkey[1], dkey[2])
            if rev_dkey not in self.deliver_sm_resp:
                result.append({
                    'sequence_number': dkey[0],
                    'timestamp': dsm['timestamp'],
                    'src': f"{dsm['src_ip']}:{dsm['src_port']}",
                    'dst': f"{dsm['dst_ip']}:{dsm['dst_port']}",
                    'message_id': dsm['message_id']
                })
        return result
    
    def save_results(self, output_data: Dict[str, List[Dict[str, Any]]]):
        """Save results to CSV files with memory optimization"""
        logger.info("Saving results to CSV files...")
        
        os.makedirs(self.output_dir, exist_ok=True)
        
        for filename, data in output_data.items():
            if data:  # Only create files with data
                filepath = f"{self.output_dir}/{filename}.csv"
                # Use chunksize for large datasets
                if len(data) > 10000:
                    df = pd.DataFrame(data)
                    df.to_csv(filepath, index=False, chunksize=5000)
                else:
                    pd.DataFrame(data).to_csv(filepath, index=False)
                logger.info(f"Saved {filename}.csv ({len(data)} records)")
    
    def print_summary(self):
        """Print summary statistics"""
        print("\n📊 Summary Statistics:")
        print(f"Total Submit SM             : {self.counters['submit_sm']:,}")
        print(f"Total Submit SM Responses   : {self.counters['submit_sm_resp']:,}")
        print(f"Total Deliver SM            : {self.counters['deliver_sm']:,}")
        print(f"Total Deliver SM Responses  : {self.counters['deliver_sm_resp']:,}")
        print(f"✅ Fully Matched Chains      : {self.counters['full_chains']:,}")
        print(f"⚠️  Partially Matched Chains : {self.counters['partial_chains']:,}")
        
        if self.delta_submit_resp:
            avg_delta = sum(self.delta_submit_resp) / len(self.delta_submit_resp)
            print(f"\n⏱ Avg Time Submit → Submit_Resp: {avg_delta:.3f}s")
        
        if self.delta_resp_deliver:
            avg_delta = sum(self.delta_resp_deliver) / len(self.delta_resp_deliver)
            print(f"⏱ Avg Time Submit_Resp → Deliver: {avg_delta:.3f}s")
        
        if self.delta_deliver_resp:
            avg_delta = sum(self.delta_deliver_resp) / len(self.delta_deliver_resp)
            print(f"⏱ Avg Time Deliver → Deliver_Resp: {avg_delta:.3f}s")
    
    def run(self, pcap_files: List[str], max_workers: int = 2):
        """Main execution method with conservative threading"""
        logger.info(f"Starting SMPP analysis with {len(pcap_files)} files")
        
        # Use conservative threading to avoid TShark crashes
        # TShark can be unstable with high concurrency
        if len(pcap_files) > 3 and max_workers > 1:
            # Limit to max 2 workers to prevent TShark instability
            actual_workers = min(2, max_workers)
            logger.info(f"Using limited multithreading with {actual_workers} workers")
            self._run_multithreaded(pcap_files, actual_workers)
        else:
            logger.info("Using single-threaded processing")
            self._run_single_threaded(pcap_files)
        
        # Build chains and generate output
        chain_records = self.build_chains()
        output_data = self.generate_output_data(chain_records)
        self.save_results(output_data)
        self.print_summary()
        
        logger.info("Analysis completed successfully!")
    
    def _run_single_threaded(self, pcap_files: List[str]):
        """Process files sequentially"""
        for pcap_file in pcap_files:
            if not self.parse_pcap_file(pcap_file):
                logger.warning(f"Failed to process {pcap_file}")
    
    def _run_multithreaded(self, pcap_files: List[str], max_workers: int):
        """Process files with conservative multithreading"""
        successful = 0
        failed = 0
        
        # Process files in smaller groups to reduce TShark load
        import time
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Process files in chunks to avoid overwhelming TShark
            chunk_size = max_workers * 2
            
            for i in range(0, len(pcap_files), chunk_size):
                chunk = pcap_files[i:i + chunk_size]
                
                # Submit chunk tasks
                future_to_file = {
                    executor.submit(self.parse_pcap_file, pcap_file): pcap_file 
                    for pcap_file in chunk
                }
                
                # Process completed tasks for this chunk
                for future in as_completed(future_to_file):
                    pcap_file = future_to_file[future]
                    try:
                        if future.result():
                            successful += 1
                            logger.info(f"✅ Successfully processed {pcap_file}")
                        else:
                            failed += 1
                            logger.warning(f"❌ Failed to process {pcap_file}")
                    except Exception as e:
                        failed += 1
                        logger.error(f"❌ Exception processing {pcap_file}: {e}")
                
                # Small delay between chunks to let TShark recover
                if i + chunk_size < len(pcap_files):
                    logger.info("Pausing briefly between file chunks...")
                    time.sleep(1)
        
        logger.info(f"Processing completed: {successful} successful, {failed} failed")


def main():
    """Main function to run the optimized SMPP parser"""
    # Generate PCAP file list
    pcap_files = [
        f"v2smpp33.pcap"
        for i in range(0, 22)
    ]
    
    # Filter existing files
    existing_files = [f for f in pcap_files if os.path.exists(f)]
    if not existing_files:
        logger.error("No PCAP files found!")
        return
    
    logger.info(f"Found {len(existing_files)} PCAP files to process")
    
    # Initialize parser and run
    parser = SMPPParser(output_dir=".")
    
    # Conservative threading - TShark can be unstable with high concurrency
    # For 22 files, use single-threaded for maximum stability
    # Or use max 2 workers if you want some parallelism
    use_threading = len(existing_files) > 5
    max_workers = 2 if use_threading else 1
    
    logger.info(f"Processing mode: {'Multithreaded' if use_threading else 'Single-threaded'}")
    parser.run(existing_files, max_workers=max_workers)


if __name__ == "__main__":
    main()
