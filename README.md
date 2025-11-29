You shouldn't have to do this but just in case:
To create a **JWT secret**, open a terminal (PowerShell) and run node -e 'console.log(require("crypto").randomBytes(32).toString("hex"))', 
copy the long hex string it prints. Then set it as an environment variable before deploying by running; $env:JWT_SECRET="paste-that-hex-string-here" in the terminal.
