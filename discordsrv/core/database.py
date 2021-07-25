import mysql.connector

class Database():
    def __init__(self, db_config):
        self.dbconfig = db_config

    async def get_linked(self, db_table, member):
        mydb = mysql.connector.connect(**self.db_config)
        mycursor = mydb.cursor(dictionary=True)
        sql = "SELECT * FROM {} WHERE discord ='{}'".format(db_table, member)
        mycursor.execute(sql)
        myresult = mycursor.fetchall()
        mydb.close()
        return myresult[0]
    