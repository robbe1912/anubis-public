function getData(): Promise<{ data: number }> {
  return new Promise((resolve, reject) => {
    setTimeout(() => {
      try {
        resolve({ data: 42 });
      } catch (err) {
        reject(err);
      }
    }, 100);
  });
}
