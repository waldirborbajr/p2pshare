# p2pshare
P2P File Share with Security

```bash
# Receive mode (listener)
go run p2pshare.go -listen :4444

# Send mode (connector pushes file)
go run p2pshare.go -connect host:4444 -send ./myfile.zip

# Listener pushes, connector pulls
go run p2pshare.go -listen :4444 -send ./myfile.zip
go run p2pshare.go -connect host:4444 -recv
```
