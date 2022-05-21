# php2go
GoLang alternatives for PHP functions

# Install

```
go get -u github.com/cexll/php2go
```

# Example

```go
hash, _ := php2go.PasswordHash("123456")
fmt.Println(hash)

// $2a$10$Fo5jPWgqCpX3Rn/0ulx37OE9Ktbv.J.hnJ6Pd3rqqedlu0WwfHx5G
```

# License
Apache License Version 2.0, http://www.apache.org/licenses/