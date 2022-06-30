# TsLsUsers
List Windows Terminal Server (RDS/RDP) users and logoff

*TsLsUsers* is a better version of `query user` or `quser` or `logoff` windows command.
With TsLsUsers you can list all users connected to a remote desktop server or disconnect all of them.

It can be scheduled to logoff all RDP/TS  users during the night, for example.

## Download
A precompiled version can be downloaded [here](https://github.com/giox069/TsLsUsers/releases/latest)

## Usage examples
`tslsusers` show connected users in text tabular format

`tslsusers /csv` show connected users in csv table format

`tslsusers /json` show connected users in JSON format

`tslsusers /outfile:filename.txt` send the output to filename.txt

`tslsusers /logoff` logoff all connected users, except the current session



