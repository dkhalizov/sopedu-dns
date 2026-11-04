# Run inside the Pi-hole container: disable the default adlist (gravity rows
# reference it, so it cannot be deleted), add the shared lists and rebuild
# gravity. Usage: sh pihole-lists.sh BASE_URL
set -e
db=/etc/pihole/gravity.db
pihole-FTL sqlite3 "$db" "UPDATE adlist SET enabled = 0;"
for f in filter_1 filter_24 filter_27 filter_51; do
  pihole-FTL sqlite3 "$db" "INSERT INTO adlist (address, enabled, comment) VALUES ('$1/$f.txt', 1, 'bench');"
done
pihole -g >/dev/null
