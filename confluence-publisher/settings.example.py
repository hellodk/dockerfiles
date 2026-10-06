"""
Confluence connection details for publish_confluence.py

Fill in the values for YOUR Confluence and delete nothing you might need.
This file is imported as a module, so keep it valid Python.

The script never prints these values. Do not commit this file to git.

-------------------------------------------------------------------------------
CONFLUENCE CLOUD  (site URL looks like https://name.atlassian.net/wiki)
-------------------------------------------------------------------------------
    CONFLUENCE_BASE_URL = "https://name.atlassian.net/wiki"
    AUTH_TYPE           = "cloud"
    EMAIL               = "you@example.com"      # your Atlassian account email
    API_TOKEN           = "..."                  # account.atlassian.com -> API tokens

-------------------------------------------------------------------------------
CONFLUENCE DATA CENTER / SERVER  (self-hosted, no atlassian.net)
-------------------------------------------------------------------------------
    CONFLUENCE_BASE_URL = "https://confluence.example.com"
    AUTH_TYPE           = "pat"                  # "pat"  -> personal access token
                                                 # "basic" -> username + password
    PAT                 = ""                     # auth: profile -> Personal Access Tokens
    USERNAME            = ""                     # only for AUTH_TYPE = "basic"
    PASSWORD            = ""                     # only for AUTH_TYPE = "basic"
"""

# ---------------------------------------------------------------- connection --
CONFLUENCE_BASE_URL = "https://YOUR-SITE.atlassian.net/wiki"

# "cloud" -> Atlassian Cloud (email + API token)
# "pat"   -> Data Center personal access token
# "basic" -> Data Center username + password
AUTH_TYPE = "cloud"

# Cloud credentials
EMAIL = "you@example.com"
API_TOKEN = "REPLACE_WITH_API_TOKEN"

# Data Center credentials
PAT = ""
USERNAME = ""
PASSWORD = ""

# --------------------------------------------------------------------- page --
SPACE_KEY = "TEAM"
PAGE_TITLE = "Distroless Base Image Findings"

# Optional: numeric id of the parent page. Leave as None to publish at the
# top level of the space. The script never guesses a parent id.
PARENT_PAGE_ID = None

# ------------------------------------------------------------------- options --
# Version label stamped on the footer of the published page.
REPORT_VERSION = "1.0.0"

# There is no in-file switch for a connection check. Use the CLI flag instead:
#     python3 publish_confluence.py --test
