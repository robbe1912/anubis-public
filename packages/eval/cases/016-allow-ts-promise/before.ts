function getData(cb) {
  setTimeout(() => cb(null, { data: 42 }), 100);
}
