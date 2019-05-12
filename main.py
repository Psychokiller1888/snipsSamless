# -*- coding: utf-8 -*-

"""
Copyright 2019 Psycho(Laurent Chervet)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

import json
import os
import requests
import toml
import uuid


class SnipsConsole:

	def __init__(self):
		self._tries = 0
		self._connected = False
		self._user = None
		self._email = ''
		self._password = ''
		self._headers = {
			'Accept'      : 'application/json',
			'Content-Type': 'application/json'
		}

		self._confFile = '/etc/snips.toml'
		if not os.path.isfile(self._confFile):
			self._confFile = 'snips.toml'

		mode = 'r' if os.path.exists(self._confFile) else 'w+'
		with open(self._confFile, mode) as f:
			self._snips = toml.load(f)


		if 'console' in self._snips and 'console_token' in self._snips['console']:
			self._headers['Authorization'] = 'JWT {}'.format(self._snips['console']['console_token'])
			self._user = User({
				'id': self._snips['console']['user_id'],
				'email': self._snips['console']['user_email']
			})
			self._connected = True
		else:
			self._login()

	@property
	def email(self) -> str:
		return self._email


	@email.setter
	def email(self, email: str):
		self._email = email


	@property
	def password(self) -> str:
		return self._password


	@password.setter
	def password(self, password: str):
		self._password = password


	def _login(self):
		self._tries += 1
		if self._tries > 3:
			print('Max login tries reached, aborting')
			self._tries = 0
			return

		payload = {
			'email'   : self.email,
			'password': self.password
		}

		req = self._req(url='v1/user/auth', data=payload)
		if req.status_code == 200:
			print('Connected to snips account, fetching auth token')
			try:
				token = req.headers['authorization']
				self._user = User(json.loads(req.content)['user'])
				accessToken = self._getAccessToken(token)
				if len(accessToken) > 0:
					print('Console token aquired, saving it!')
					if 'console' not in self._snips:
						self._snips['console'] = {}

					self._snips['console']['console_token'] = accessToken['token']
					self._snips['console']['console_alias'] = accessToken['alias']
					self._snips['console']['user_id'] = self._user.userId
					self._snips['console']['user_email'] = self._user.userEmail

					self._headers['Authorization'] = 'JWT {}'.format(accessToken['token'])
					self._saveSnipsConf()
					self._connected = True
					self._tries = 0
				else:
					raise Exception('Error getting JWT console token')
			except Exception as e:
				print('Exception during console token aquiring: {}'.format(e))
				self._connected = False
				return
		else:
			print("Couldn't connect to console: {}".format(req.status_code))
			self._connected = False


	def _getAccessToken(self, token: str) -> dict:
		alias = 'samless-{}'.format(str(uuid.uuid4())).replace('-', '')[:29]
		self._headers['Authorization'] = token
		req = self._req(url='v1/user/{}/accesstoken'.format(self._user.userId), data={'alias': alias})
		if req.status_code == 201:
			return json.loads(req.content)['token']
		return {}


	def _saveSnipsConf(self):
		with open(self._confFile, 'w') as f:
			toml.dump(self._snips, f)


	def _req(self, url: str = '', method: str = 'post', data: dict = None, **kwargs) -> requests.Response:
		req = requests.request(method=method, url='https://external-gateway.snips.ai/{}'.format(url), json=data, headers=self._headers, **kwargs)
		if req.status_code == 401:
			print('Console token expired or refused, need to login again')
			if 'Authorization' in self._headers:
				del self._headers['Authorization']
			self._connected = False

			if 'console' in self._snips:
				self._snips['console']['console_token'] = ''
				self._snips['console']['console_alias'] = ''
				self._snips['console']['user_id'] = ''
				self._snips['console']['user_email'] = ''
				self._saveSnipsConf()

			self._login()
		return req


	def listAssistants(self):
		req = self._req(url='/v3/assistant', method='get', data={'userId': self._user.userId})
		assistants = json.loads(req.content)
		print(assistants)


	def nluStatus(self, assistantId: str):
		req = self._req(url='/v3/assistant/{}/status'.format(assistantId), method='get')
		print(req.content)


	def asrStatus(self, assistantId: str):
		req = self._req(url='/v1/languagemodel/status', data={'assistantId': assistantId}, method='get')
		print(req.content)
		print(req.status_code)


	def nluTraining(self, assistantId: str):
		req = self._req(url='/v1/training', data={'assistantId': assistantId})
		print(req.content)
		print(req.status_code)


	def asrTraining(self, assistantId: str):
		req = self._req(url='/v1/languagemodel', data={'assistantId': assistantId})
		print(req.content)
		print(req.status_code)


	def download(self, assistantId: str):
		req = self._req(url='/v3/assistant/{}/download'.format(assistantId), method='get')
		with open('assistant.zip', 'wb') as f:
			f.write(req.content)


	def logout(self):
		req = self._req(url='/v1/user/{}/accesstoken/{}'.format(self._user.userId, self._snips['console']['console_alias']), method='get')
		if 'Authorization' in self._headers:
			del self._headers['Authorization']
		self._connected = False

		if 'console' in self._snips:
			self._snips['console']['console_token'] = ''
			self._snips['console']['console_alias'] = ''
			self._snips['console']['user_id'] = ''
			self._snips['console']['user_email'] = ''
			self._saveSnipsConf()
		print(req.content)


	def login(self):
		if self._connected:
			print('You are already logged in')
		else:
			self._login()


class User:
	def __init__(self, data):
		self._userId = data['id']
		self._userEmail = data['email']


	@property
	def userId(self) -> str:
		return self._userId

	@property
	def userEmail(self) -> str:
		return self._userEmail


if __name__ == '__main__':
	running = True
	console = SnipsConsole()
	print('Commands: email, password, login, logout, list, nlu status, asr status, nlu training, asr training, download')
	while running:
		cmd = input('Command: ')
		if cmd == 'email':
			console.email = input('Enter your snips console account email: ')
		elif cmd == 'password':
			console.password = input('Enter your snips console account password: ')
		elif cmd == 'list':
			console.listAssistants()
		elif cmd == 'nlu status':
			arg = input('Assistant id: ')
			console.nluStatus(arg)
		elif cmd == 'asr status':
			arg = input('Assistant id: ')
			console.asrStatus(arg)
		elif cmd == 'nlu training':
			arg = input('Assistant id: ')
			console.nluTraining(arg)
		elif cmd == 'asr training':
			arg = input('Assistant id: ')
			console.asrTraining(arg)
		elif cmd == 'download':
			arg = input('Assistant id: ')
			console.asrTraining(arg)
		elif cmd == 'logout':
			console.logout()
		elif cmd == 'login':
			console.login()