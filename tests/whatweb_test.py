"""Unittests for whatweb agent."""

import tempfile

from ostorlab.agent import message as msg

OUTPUT = '''["http://10fastfingers.com",301,[["IP",[{"string":"104.26.4.9","certainty":100}]],["HTTPServer",[{"name":"server string","string":"cloudflare","certainty":100}]],["RedirectLocation",[{"name":"location","string":"https://10fastfingers.com/","certainty":100}]],["UncommonHeaders",[{"name":"headers","string":"report-to,nel,cf-ray","certainty":100}]],["Country",[{"string":"UNITED STATES","module":"US","certainty":100}]]]]
["https://10fastfingers.com/",200,[["PHPCake",[{"name":"CAKEPHP Cookie","certainty":100}]],["IP",[{"string":"104.26.5.9","certainty":100}]],["Via-Proxy",[{"search":"headers[via]","string":["1.1 8e20810f1edd66323991c4412691bb48.cloudfront.net (CloudFront)"],"regexp_compiled":"(?-mix:^.*$)","certainty":100}]],["Script",[{"regexp":[" ",">"],"regexp_compiled":"(?i-mx:<script(\\s|>))","certainty":100},{"string":["text/javascript"],"offset":1,"regexp_compiled":"(?-mix:<script[^>]+(language|type)\\s*=\\s*['\"]?([^'\"\\s]+)['\"]?)","certainty":100}]],["HTTPServer",[{"name":"server string","string":"cloudflare","certainty":100}]],["HTML5",[{"regexp":["<!DOCTYPE html>"],"regexp_compiled":"(?i-mx:<!DOCTYPE html>)","certainty":100}]],["Cookies",[{"string":"CAKEPHP","certainty":100},{"string":"CakeCookie[lang]","certainty":100}]],["Bootstrap",[{"regexp":["<link rel=\"stylesheet\" href=\"//cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.0.3/css/bootstrap"],"regexp_compiled":"(?-mix:<link [^>]*bootstrap)","certainty":100},{"version":["3.0.3"],"offset":0,"regexp_compiled":"(?-mix:bootstrap\\/([0-9\\.]+)(\\/css)?\\/bootstrap(\\.min)?\\.css)","certainty":100}]],["HttpOnly",[{"string":[["CAKEPHP"]],"certainty":100}]],["UncommonHeaders",[{"name":"headers","string":"x-amz-cf-pop,x-amz-cf-id,cf-cache-status,expect-ct,report-to,nel,cf-ray","certainty":100}]],["Country",[{"string":"UNITED STATES","module":"US","certainty":100}]],["Google-Analytics",[{"version":"Universal","account":["UA-179742-52"],"regexp_compiled":"(?-mix:ga\\([\\s]*'create',[\\s]*'(\\w{2}-\\d{1,}-\\d{1,})',)","certainty":100}]],["Title",[{"name":"page title","string":"10FastFingers.com - Typing Test, Competitions, Practice & Typing Games","certainty":100}]]]]'''


def testWhatWebAgent_allChecks_emitsFingerprints(whatweb_test_agent, mocker):
    """Test the whatweb agent with a given target address"""

    input_selector = 'v3.asset.domain_name'
    input_data = {'name': 'ostorlab.co',}

    output_selector = 'v3.fingerprint.domain_name.library'
    output_data = {
        'domain_name': 'ostorlab.co',
        'library_name': 'UNITED STATES',
        'library_version': '',
        'library_type': 'BACKEND_COMPONENT'
    }

    message = msg.Message.from_data(selector=input_selector, data=input_data)
    mocker.patch('subprocess.run', return_value=None)
    mock_emit = mocker.patch('agent.whatweb.WhatWebAgent.emit', return_value=None)
    with tempfile.TemporaryFile() as fp:
        mocker.patch('tempfile.TemporaryFile', return_value=fp)
        fp.write(OUTPUT.encode())
        fp.seek(0)
        whatweb_test_agent.process(message)
        mock_emit.assert_called_with(selector=output_selector, data=output_data)

