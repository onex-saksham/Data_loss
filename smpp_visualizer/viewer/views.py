import csv
import os
from types import SimpleNamespace
from django.shortcuts import render
from django.conf import settings

CSV_PATH = os.path.join(settings.BASE_DIR, 'smpp_full_chains.csv')
import subprocess
import os
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.contrib import messages

@csrf_exempt
def generate_csv(request):
    if request.method == 'POST':
        dir_input = request.POST.get('dir_input', '').strip()
        script_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'old.py')

        # Build the command
        cmd = ['python3', script_path]
        if dir_input:
            cmd.append(dir_input)

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            messages.success(request, f"✅ CSV generated successfully!\n{result.stdout}")
        except subprocess.CalledProcessError as e:
            messages.error(request, f"❌ Error generating CSV:\n{e.stderr}")
        
        return HttpResponseRedirect(reverse('search_page'))

def search_page(request):
    if request.method == 'POST':
        query = request.POST.get('query', '').strip()
        id_list = [mid.strip() for mid in query.split(',') if mid.strip()]

        results = []
        with open(CSV_PATH, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            header = reader.fieldnames
            for row in reader:
                # Normalize both sides to avoid mismatches due to spaces/case
                row_id = row.get('message_id', '').strip()
                if row_id in id_list:
                    results.append(SimpleNamespace(**row))

        return render(request, 'search.html', {
            'results': results,
            'header': header,
            'query': query
        })

    return render(request, 'search.html')
