# WHMCS_Trojan_Admin
Make WHMCS Great Again.

### Important Notification
Please move the products_JSON.php to a directory unreachable by web access. Otherwise your password will be exposed to everyone!

### MySQL Structure
Table: users

+---+----------+------------+------------+------+---------+----------------+
| # | Name     | Type       | Attributes | Null | Default | Extra          |
+---+----------+------------+------------+------+---------+----------------+
| 1 | id #     | int(10)    | UNSIGNED   | No   | None    | AUTO_INCREMENT |
+---+----------+------------+------------+------+---------+----------------+
| 2 | password | char(56)   |            | No   | None    |                |
+---+----------+------------+------------+------+---------+----------------+
| 3 | quota    | bigint(20) |            | No   | 0       |                |
+---+----------+------------+------------+------+---------+----------------+
| 4 | download | bigint(20) |            | No   | 0       |                |
+---+----------+------------+------------+------+---------+----------------+
| 5 | upload   | bigint(20) |            | No   | 0       |                |
+---+----------+------------+------------+------+---------+----------------+
| 6 | pid      | int(11)    |            | No   | 0       |                |
+---+----------+------------+------------+------+---------+----------------+
