class Config:
    """ Configuration class """
    DEFENDER_OAUTH_RESOURCE: str = "https://api.securitycenter.microsoft.com"
    DEFENDER_API_BASE_URL: str = "https://api.security.microsoft.com"
    PS_SCRIPT_NAME: str = 'ANYRUN-SB-DEFENDER.ps1'
    BASH_SCRIPT_NAME: str = 'ANYRUN-SB-DEFENDER.sh'
    VERSION: str = 'MS_Defender:1.0.0'

    ACTION_TIMEOUT: int = 30
