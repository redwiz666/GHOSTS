# Windows Management Instrumentation (WMI) Configuration

???+ info "Sample Configuration"
    The sample configuration below is also available in the [GHOSTS GitHub repository](<https://github.com/cmu-sei/GHOSTS/blob/master/src/Ghosts.Client/Sample%20Timelines/clicks>

Each CommandArg is of the formation shown below, if multiple CommandArgs are present a random one is chosen for execution on each cycle.
Credential handling is done in the same manner as the SSH handler, see that sample timeline for documentation.
After the `cred_key` is a ';' delimited list of WMI commands that are executed in sequence during a cycle.

Supported commands:

- GetOperatingSystem
- GetBios
- GetProcessor
- GetUserList
- GetNetworkInfo
- GetFilesList
- GetProcessList

The credentials file uses the same format as SFTP/SSH, but requires a 'domain' keyword in addition to 'username', 'password'
For this to work, the target host needs to be configured to allow WMI
The domain admin is the best choice for username/password
The trusted hosts of the VM running GHOSTS must be set to include the IPs of any of the hosts being interrogated by WMI

You can print the Trusted hosts if the current host by executing in Powershell:

- winrm g winrm/config/client

You can set Trusted Hosts to a wild card (trust all hosts) by executing in Powershell:

- winrm s winrm/config/client '@{TrustedHosts="*"}'


```json
{
  "Status": "Run",
  "TimeLineHandlers": [
    {
      "HandlerType": "Wmi",
      "HandlerArgs": {
        "TimeBetweenCommandsMax": 5000, //max,min between individual WMI commands
        "TimeBetweenCommandsMin": 1000,
        "CredentialsFile": "<path to credentials>", //required, file path to a JSON file containing the WMI credentials
        "delay-jitter": 0 //optional, default =0, range 0 to 50, if specified, DelayAfter varied by delay-%jitter*delay to delay+%jitter*delay
      },
      "Initial": "",
      "UtcTimeOn": "00:00:00",
      "UtcTimeOff": "24:00:00",
      "Loop": "True",
      "TimeLineEvents": [
        {
          "Command": "random",
          "CommandArgs": [
            "<someIp>|<credKey>|<a_cmd>;<a_cmd>;<a_cmd>....;<a_cmd>"
          ],
          "DelayAfter": 20000,
          "DelayBefore": 0
        }
      ]
    }

  ]
}
```
