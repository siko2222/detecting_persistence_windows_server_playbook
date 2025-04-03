# Serving of files
All files to be downloaded using the addPersistence scripts was server on the Linux server using a simple python webserver
```bash
mkdir fileshare
cd fileshare
nohup python3 -m http.server --bind 0.0.0.0 9000 &
```
