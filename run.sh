docker build -t multiarch-dev .

docker run --rm -it \
  -v "$(pwd)/shared:/shared" \
  multiarch-dev 
  