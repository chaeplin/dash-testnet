https://distracted-it.blogspot.kr/2015/05/iptables-firewall-rules-for-busy.html
https://serverfault.com/questions/234560/how-to-turn-iptables-stateless

```
*raw
:PREROUTING ACCEPT [2850071740:298465624140]
:OUTPUT ACCEPT [2845494189:315540412911]
-A PREROUTING -i lo -j NOTRACK
-A OUTPUT -o lo -j NOTRACK
COMMIT
```

