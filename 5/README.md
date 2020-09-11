# Day 5 - Wintertime

Due to the way `StringBuilder` is implememted, if a very large delimiter is supplied, it can cause a DoS condition. Since delimiter is appended to the `StringBuilder` class after every iteration, if it was prohibitably large, it can cause memory exhaustion.