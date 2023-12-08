# MSVulnDownloader

1. Run def365-vuln-downloader.ps1 or defcloud-vuln-downloader.ps1
2. The script will prompt you to login to azure to create a new Azure App 
   1. The app name can be changed on line 4 if desired
   2. if the app doesn't exist, ensure the logged in user has permission to create new apps and set permissions
3. Troubleshooting:
   1. There are some files that are cached that may need to be deleted:
      1. defcloud-subassessments.csv
      2. json files inside of /subassessments directory
      3. vulnerabilityDetailsDictionary.json
   2. Sometimes the token needs to be reset. You can run $tokenJson='' or simply restart your PowerShell session
   3. 