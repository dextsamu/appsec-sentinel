resource "aws_security_group" "x" {
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_s3_bucket" "b" {
  acl = "public-read"
}
resource "aws_db_instance" "d" {
  password = "VALORE-IAC-DI-PROVA"
}
