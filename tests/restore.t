# Check multi-set restore
0 ipset restore < restore.t.multi
# Save sets and compare
0 ipset save > .foo && diff restore.t.multi.saved .foo
# Delete all sets
0 ipset -x
# eof
