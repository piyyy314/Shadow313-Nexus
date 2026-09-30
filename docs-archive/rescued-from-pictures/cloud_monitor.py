import boto3, time
from ..core.log_util import log_event

def aws_guardduty_monitor(rc, region='us-east-1'):
    client = boto3.client('guardduty', region_name=region)
    detector_id = client.list_detectors()['DetectorIds'][0]
    seen = set()
    while True:
        findings = client.list_findings(DetectorId=detector_id)['FindingIds']
        new_findings = [f for f in findings if f not in seen]
        if not new_findings:
            time.sleep(60)
            continue
        descs = client.get_findings(DetectorId=detector_id, FindingIds=new_findings)['Findings']
        for finding in descs:
            inst = finding['Resource']['InstanceDetails']['InstanceId']
            log_event(f"[CLOUD_MONITOR] Malicious activity on {inst}")
            rc.handle_alert("cloud_quarantine", {"instance_id": inst})
            seen.add(finding['Id'])
        time.sleep(30)