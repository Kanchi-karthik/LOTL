MITRE_MAP = {

"curl":"T1105 Ingress Tool Transfer",

"cat":"T1003 Credential Dumping",

"chmod":"T1222 File Permission Modification",

"bash":"T1059 Command Execution"

}

def map_command(cmd):

    return MITRE_MAP.get(cmd,"Unknown Technique")
