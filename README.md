# Sigma Service

This assemblyline service automates detection of Windows Sysmon Event logs that indicate malicious behavior.

### How does it work?
This service utilizes our pysigma library https://github.com/CybercentreCanada/pysigma to check Windows Sysmon Event logs against a Sigma ruleset. 
The sigma rules are found from a list of sources defined in the service_manifest.yml. Currently all the rules used in the service are found from https://github.com/SigmaHQ/sigma/tree/master/rules/windows

**NOTE**: This service does not require you to buy any licence and is preinstalled and
working after a default installation
