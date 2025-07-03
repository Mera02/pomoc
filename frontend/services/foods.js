var FoodsService = {
  getReport: function(page = 1, limit = 10, success, error) {
    fetch(`/foods/report?page=${page}&limit=${limit}`)
      .then(res => {
        if (!res.ok) throw new Error("Network response was not ok");
        return res.json();
      })
      .then(data => success(data))
      .catch(err => {
        if (error) error(err);
        else console.error("FoodsService error:", err);
      });
  }
};
