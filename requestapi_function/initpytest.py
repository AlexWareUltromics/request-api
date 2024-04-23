import json
import azure.functions as func
import logging
import requests
import re
from urllib.parse import urlparse, parse_qs


def main(req: func.HttpRequest) -> func.HttpResponse:
    
    status_code = ''

#req = func.HttpRequest(
#    method='POST',
#    body={
#    'service': 'JSON',
#    'product': 'EchoGo Heart Failure',
#    'accession': 'UOC-4441',
#    'studyinstanceuid': ''
#    },
#    url='https://result-api.dev.ultromics.net/api/QueryResults',
#    headers={'Content-Type': 'application/json'},
#    params=''
#)
    method = req.method
    if method not in ('GET','POST'):
        status_code = 400
        logging.info('verb issue')
        return func.HttpResponse(f"Function returned with status code: {status_code}")
    url = req.url
    expectedkeys = ['service','product','accession','studyinstanceuid']
    #for key, value in req.headers.items():
    #    header_value = ''
    #    logging.info('header_key: '+str(key)+', header_value: '+str(value))
    #    if str(key).lower() == 'content-type' and str(value).lower in ('application/json','application/x-www-form-urlencoded'):
    #        header_value = value

    if 'Content-Type' in req.headers and req.headers['Content-Type'].lower() in ('application/json', 'application/x-www-form-urlencoded'):
        header_value = req.headers['Content-Type']
        logging.info('header: '+str(header_value))

    if 'content-type' in req.headers and req.headers['content-type'].lower() in ('application/json', 'application/x-www-form-urlencoded'):
        header_value = req.headers['content-type']
        logging.info('header: '+str(header_value))
    
    logging.info('METHOD: '+str(method))
    if method == 'GET':
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        suppliedkeys = query_params.keys()
        service = query_params['service'][0]
        product = query_params['product'][0]
        accession = query_params['accession'][0]
        studyinstanceuid = query_params['studyinstanceuid'][0]

    if method == 'POST':

        # Assuming req.get_body() returns a bytes object
        body_bytes = req.get_body()
        body_str = body_bytes.decode('utf-8')  # Decode bytes to string assuming utf-8 encoding
        body_dict = json.loads(body_str)  # Parse the JSON string into a Python dictionary
        logging.info(str(body_dict))
        #if isinstance(body, dict):
        #    suppliedkeys = body.keys()
        #    logging.info(str(suppliedkeys))
        try:
            suppliedkeys = body_dict.keys()
        except Exception as e:
            logging.info(str(e))
            status_code = 400
            return func.HttpResponse(f"Function returned with status code: {status_code}")


        logging.info(str(suppliedkeys))
        #service = req.get_body()['service']
        service = body_dict.get('service')  
        #product = req.get_body()['product']
        product = body_dict.get('product')
        #accession = req.get_body()['accession']
        accession = body_dict.get('accession')
        #studyinstanceuid = req.get_body()['studyinstanceuid']
        studyinstanceuid = body_dict.get('studyinstanceuid')
    
    missing_keys = [key for key in expectedkeys if key not in suppliedkeys]
    if len(missing_keys) > 0:
        status_code = 400
        logging.info(str(missing_keys) + ' is/are missing - incomplete request')
        return func.HttpResponse(f"Function returned with status code: {status_code}")
    extra_keys = [key for key in suppliedkeys if key not in expectedkeys]
    if len(extra_keys) > 0:
        status_code = 400
        logging.info('Extra key(s) '+str(extra_keys)+ ' is/are in the request - invalid request')
        return func.HttpResponse(f"Function returned with status code: {status_code}")
    
    customer_code = accession.split('-')[0]
    #logging.info('header value is: ' + str(header_value))
    if header_value not in ('application/json','application/x-www-form-urlencoded'):
        status_code = 400
        logging.info('header issue')
        return func.HttpResponse(f"Function returned with status code: {status_code}")

    if service not in ('HL7','Dicom','JSON'):
        status_code = 400
        logging.info('service issue')
        return func.HttpResponse(f"Function returned with status code: {status_code}")

    if not re.match(r'^[A-Za-z]{3,4}-\d{1,4}$', accession):
        status_code = 400
        logging.info('order id issue')
        return func.HttpResponse(f"Function returned with status code: {status_code}")

    if isinstance(accession, list):
        status_code = 400
        logging.info('multiple accessions requested.')
        return func.HttpResponse(f"Function returned with status code: {status_code}")

    if not url.startswith('https://') or not re.match(r'https://[A-Za-z0-9.-]+\.[A-Za-z]{2,}', url):
        status_code = 400
        logging.info('url issue')
        return func.HttpResponse(f"Function returned with status code: {status_code}")

    if product not in ('EchoGo Heart Failure'):
        status_code = 400
        logging.info('software req issue')
        return func.HttpResponse(f"Function returned with status code: {status_code}")

    data = {
        'order': accession,
        'software': product
    }

    logging.info(url)
    logging.info(data)
    response = requests.post(url, json=data,allow_redirects=False)
    response_text = response.text
    x = response.content
    logging.info("Response Text:"+ response_text)
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as errh:
        status_code = 404
        logging.info ("Http Error:",errh)
        return func.HttpResponse(f"Function returned with status code: {status_code}")

    try:
        json_data = json.loads(response_text)
    except json.JSONDecodeError as e:
        logging.error("JSON Decode Error:" + str(e))
        status_code = 404
        logging.info('no results returned')
        return func.HttpResponse(f"Function returned with status code: {status_code}")

    if len(json_data) == 0:
        status_code = 404
        logging.info('no results returned')
        return func.HttpResponse(f"Function returned with status code: {status_code}")

    for item in json_data:
        outcome = ''
        if item['accepted'] == True:
            outcome = 'Positive'
        if item['accepted'] == False:
            outcome = 'Negative'

        item['ultromicsid'] = item.pop('accession')
        item['outcome'] = outcome
        item.pop('accepted')
        item['product'] = item['software'] + ' - ' + item.pop('version')
        item['rejection'] = item.pop('reason')
        item['studyinstanceuid'] = item.pop('suid')
        item['created'] = item.pop('received')


    logging.info(item)
    if customer_code != item['customer']:
        status_code = 400
        logging.info('customer code not matching')
        return func.HttpResponse(f"Function returned with status code: {status_code}")
    if accession != item['ultromicsid']:
        status_code = 400
        logging.info('accession not matching')
        return func.HttpResponse(f"Function returned with status code: {status_code}")
    if product != item['software']:
        status_code = 400
        logging.info('product not matching')
        return func.HttpResponse(f"Function returned with status code: {status_code}")
    if not re.match(r'^[0-9]+\.[0-9]+\.[0-9]+$',item['sop']):
        status_code = 400
        logging.info('invalid sop format')
        return func.HttpResponse(f"Function returned with status code: {status_code}")
    if not re.match(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$',item['studyinstanceuid']):
        status_code = 400
        logging.info('invalid studyinstanceuid format')
        return func.HttpResponse(f"Function returned with status code: {status_code}")
    if not re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}$',item['created']):
        status_code = 400
        logging.info('invalid created datetime')
        return func.HttpResponse(f"Function returned with status code: {status_code}")
    
    status_code = 200
    return func.HttpResponse(f"Function returned with status code: {status_code}")
