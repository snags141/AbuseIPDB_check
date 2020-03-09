#!/usr/bin/env python

import sys
import os
import requests as req
import json
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.searchcommands import \
    dispatch, StreamingCommand, Configuration, Option, validators


@Configuration()
class abuseipCommand(StreamingCommand):

    """ %(synopsis)

    ##Syntax

    %(syntax)

    ##Description

    %(description)

    """

    ipfield = Option(
        doc='''
        **Syntax:** **ipfield=***<fieldname>*
        **Description:** Name of the IP address field to look up''',
        require=True, validate=validators.Fieldname())

    def stream(self, events):
        # Load config with user specified API key, if this file does not exist copy it from ../default
        with open('../local/config.json') as config_file:
            data = json.load(config_file)
            api_key = data['abuseip'][0]['api_key']

        # API required headers
        headers = {
            'Key': api_key,
            'Accept': 'application/json',
        }


        for event in events:
            event_dest_ip = event[self.ipfield]
            # API required parameters
            params = (
                ('ipAddress', event_dest_ip),
                ('maxAgeInDays', '90'),
                ('verbose', ''),
            )
            # Make API Request
            error=0
            response = req.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params)
            if(response.status_code == 200):
                data=response.json()
                if 'data' in data:
                    addr_country_name = data['data']['countryName']
                    addr_domain = data['data']['domain']
                    addr_isp = data['data']['isp']
                    addr_last_reported = data['data']['lastReportedAt']
                    addr_abuse_confidence = data['data']['abuseConfidenceScore']
                else:
                    error=1
                    event['AbuseApiError'] = "Invalid Response:Missing data key"
            else:
                error=1
                event['AbuseApiError'] = "Invalid Request:status_code="+str(response.status_code)
            # Set event values to be returned
            if error == 0:
                event["CountryName"] = addr_country_name
                event["Domain"] = addr_domain
                event["ISP"] = addr_isp
                event["LastReportedAt"] = addr_last_reported
                event["AbuseConfidence"] = addr_abuse_confidence

            # Finalize event
            yield event


dispatch(abuseipCommand, sys.argv, sys.stdin, sys.stdout, __name__)
