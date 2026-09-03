# revshell
A multiplatform reverse shell generator cli. Built to be easy to use, simple, lightweight, and get you hacking CTFs/Labs/Targets/Nations quicker. Currently the scope is limited to only support a linux attack box, have reverse shell parity with revshells.com, and include automatic reverse shell generation listening and handling. 

I might later add some additional logic and handling for caught listeners, but I don't want to start making my own C2, this will be lightweight and limited to CTFs and what not.

## Architecture and Setup
The CLI tool is developed in Golang 1.27.1, and built of the Cobra library and Cobra-CLI tool for initial set up and monitoring

## Security and Contributing
You are welcome to contribute with/without AI, with the guidelines being lightweight, with these being:
- Ensure you provide sufficient detail and keep contributions small
- If you see or find a vuln, email me at hi@maxfrancis.me until I set up a formal security policy through GH