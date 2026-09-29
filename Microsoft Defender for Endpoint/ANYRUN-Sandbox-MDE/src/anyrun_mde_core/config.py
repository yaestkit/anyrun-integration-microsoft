class Config:
    """ Configuration class """
    DEFENDER_OAUTH_RESOURCE: str = "https://api.securitycenter.microsoft.com"
    DEFENDER_API_BASE_URL: str = "https://api.security.microsoft.com"
    PS_SCRIPT_NAME: str = 'ANYRUN-SB-DEFENDER.ps1'
    BASH_SCRIPT_NAME: str = 'ANYRUN-SB-DEFENDER.sh'
    VERSION: str = 'MS_Defender:1.1.1'

    ACTION_TIMEOUT: int = 30
    LIVE_RESPONSE_WAIT_SECONDS: int = 900
    LIVE_RESPONSE_SUBMIT_RETRIES: int = 5
    JOB_TIME_BUDGET_SECONDS: int = 5400
