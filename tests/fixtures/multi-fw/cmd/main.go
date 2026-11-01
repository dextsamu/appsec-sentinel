package main
func main() {
  r := gin.Default()
  r.GET("/ping", ping)
  r.POST("/admin/reset", RequireAuth(reset))
}
