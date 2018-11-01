#!/usr/bin/python3
#
# Antes de usar, execute o seguinte comando para evitar que o Linux feche
# as conexoes TCP abertas por este programa:
#
# sudo iptables -I OUTPUT -p tcp --tcp-flags RST RST -j DROP
#

import asyncio
import socket
import struct
import os
import random
import time

FLAGS_FIN = 1<<0 #Flag de fim de conexao
FLAGS_SYN = 1<<1 #Flag de sicronizacao
FLAGS_RST = 1<<2 #Flag de warning socket nao existente
FLAGS_ACK = 1<<4 #Flag de resposta ACK

MSS = 1460 #Maximum Segment Size

TESTAR_PERDA_ENVIO = False

#Anotacoes
#Send coloca na fila de envio, se fila estiver vazia ja enviar. Depende da janela
conexoes = {}
class Conexao:
	def __init__(self, id_conexao, seq_no, ack_no):
		#Informacoes para a conexao
		self.id_conexao = id_conexao

		#Controle do envio de ack_no
		self.ack_no = ack_no

		#Controle de recebimento de ack_no
		self.send_base = seq_no
		#Controle de envio de seq_no
		self.next_seq_no = seq_no

		#Dicionario (seq_no, current time)
		self.dic_seq_no_curr_time = {}

		#Filas de envio
		self.send_queue = b""
		self.no_ack_queue = b""

		#Janelas
		self.cwnd = self.rwnd = 10*MSS

		#Timer
		self.timer = None

		#Flags
		#Flag handshake
		self.flag_handshake = True

		# dados da camada de aplicação
		self.http_req = b''


#Converte endereco para string
def addr2str(addr):
	return '%d.%d.%d.%d' % tuple(int(x) for x in addr)

#Converte string para endereco
def str2addr(addr):
	return bytes(int(x) for x in addr.split('.'))

#Cabecalho da camada de rede - IP Datagram Format
def handle_ipv4_header(packet):
	#Versao do procotolo IP
	version = packet[0] >> 4
	#Tamanho do Cabecalho
	ihl = packet[0] & 0xf
	#Verifica se a versao do IP eh a 4
	assert version == 4
	#Endereco fonte
	src_addr = addr2str(packet[12:16])
	#Endereco destino
	dst_addr = addr2str(packet[16:20])
	#Segmento contendo o protocolo TCP
	segment = packet[4*ihl:]

	return src_addr, dst_addr, segment

#Aceita conexao - Syn + ACK
def make_synack(conexao):
	#Monta pacote a ser enviado
	#(Formato dos dados, porta fonte, porta destino, Sequence Number, ACK Number,bit ACK e bit SYN,
	# Window Size, CheckSum, Urg data pointer)
	(src_addr, src_port, dst_addr, dst_port) = conexao.id_conexao
	return struct.pack('!HHIIHHHH', dst_port, src_port, conexao.next_seq_no, conexao.ack_no, (5<<12)|FLAGS_ACK|FLAGS_SYN,
						1024, 0, 0)

def make_ack(conexao):
	#Monta pacote a ser enviado
	#(Formato dos dados, porta fonte, porta destino, Sequence Number, ACK Number,bit ACK e bit SYN,
	# Window Size, CheckSum, Urg data pointer)
	(src_addr, src_port, dst_addr, dst_port) = conexao.id_conexao
	return struct.pack('!HHIIHHHH', dst_port, src_port, conexao.next_seq_no, conexao.ack_no, (5<<12)|FLAGS_ACK,
						1024, 0, 0)

def make_fin(conexao):
	#Monta pacote a ser enviado
	#(Formato dos dados, porta fonte, porta destino, Sequence Number, ACK Number,bit FIN,
	# Window Size, CheckSum, Urg data pointer)
	(src_addr, src_port, dst_addr, dst_port) = conexao.id_conexao
	return struct.pack('!HHIIHHHH', dst_port, src_port, conexao.next_seq_no, conexao.ack_no, (5<<12)|FLAGS_FIN|FLAGS_ACK,
						1024, 0, 0)

#Calcula CheckSum
def calc_checksum(segment):
	# se for ímpar, faz padding à direita
	if len(segment) % 2 == 1:
		segment += b'\x00'
	#Inicializa o checksum
	checksum = 0
	#Faz as somas dos campos
	for i in range(0, len(segment), 2):
		x, = struct.unpack('!H', segment[i:i+2])
		checksum += x
		#Overflow
		while checksum > 0xffff:
			checksum = (checksum & 0xffff) + 1
	#Complemento
	checksum = ~checksum
	return checksum & 0xffff

#Corrije o CheckSum
def fix_checksum(segment, src_addr, dst_addr):
	#Pseudo cabecalho
	#Endereco Fonte + Endereco Destino + (formato, Identificador TCP, Tamanho do segmento)
	pseudohdr = str2addr(src_addr) + str2addr(dst_addr) + struct.pack('!HH', 0x0006, len(segment))
	#Conversao para Byte
	seg = bytearray(segment)
	#
	seg[16:18] = b'\x00\x00'
	#
	seg[16:18] = struct.pack('!H', calc_checksum(pseudohdr + seg))

	return bytes(seg)

def send_segment(fd, conexao, segment):
	(src_addr, src_port, dst_addr, dst_port) = conexao.id_conexao
	fd.sendto(fix_checksum(segment,	src_addr, dst_addr), (src_addr, src_port))

#Separar funcao(?)
def abre_conexao(fd, id_conexao,seq_no):
	(src_addr, src_port, dst_addr, dst_port) = id_conexao

	print('%s:%d -> %s:%d (seq=%d)' % (src_addr, src_port,
											dst_addr, dst_port,seq_no))

		#Alocando nova conexao
	conexoes[id_conexao] = conexao = Conexao(id_conexao=id_conexao,
														seq_no=struct.unpack('I', os.urandom(4))[0],
														ack_no=seq_no + 1)

	send_segment(fd, conexao, make_synack(conexao))

	conexao.next_seq_no += 1

	return conexao


def fin_recv(fd, conexao, seq_no):
	if conexao.ack_no == seq_no:
		# Se tiver recebido tudo certo até aqui, incrementa 1 para informar que é um ACK do FIN
		conexao.ack_no += 1
	# Senão, o valor de ack_no terá sido mantido, fazendo com que a outra ponta saiba onde paramos de receber dados
	send_segment(fd, conexao, make_ack(conexao))


#Trata recebimento do ack_no
def ack_recv(fd, conexao, ack_no):
	if(ack_no > conexao.send_base):
		#Handshake, nenhum dado presente nas filas
		#Duvidas... o que fzr
		if(conexao.flag_handshake == True):
			conexao.send_base = ack_no
			conexao.flag_handshake = False
			print("eh na sola da bota eh na palma da bota")
		#Situacao onde a conexao já esta estabelecida
		else:
			#Dados confirmados a serem removidos da noAck_
			print("Entrei no else\n")
			qtd_dados_reconhecidos = ack_no - conexao.send_base
			#Atualiza send_base
			conexao.send_base = ack_no

			#Para timer do ultimo pacote sem resposta ack
			if conexao.timer:
				conexao.timer.cancel()
				conexao.timer = None #~(conexao.timer.cancelled())

			#Remove da fila de enviados sem confirmacao
			conexao.no_ack_queue = conexao.no_ack_queue[qtd_dados_reconhecidos:]

			print("ANTES: \n")
			print(conexao.send_queue)
			print("\n")
			print(conexao.no_ack_queue)
			print("\n")
			#send(fd,conexao,b"mensagem qualquer em binario\n")
			print("DEPOIS: \n")
			print(conexao.send_queue)
			print("\n")
			print(conexao.no_ack_queue)

			#No caso de haver mais pacotes ainda sem resposta ack, start time para o ultimo deles
			if(conexao.no_ack_queue != b''):
				print("if vazio")
				#Adicionar novo timer
				#Usar dicionario
				#Como referenciar o pacote e fazer callback?
	return



#Trata recebimento de payload
def payload_recv(conexao, seq_no, payload):
	in_order = conexao.ack_no == seq_no
	if in_order:
		conexao.ack_no += len(payload)
	send_segment(fd, conexao, make_ack(conexao))
	if in_order:
		app_recv(fd, conexao, payload)



def app_recv(fd, conexao, payload):
	conexao.http_req += payload
	if b'\n\n' in conexao.http_req or b'\r\n\r\n' in conexao.http_req:
		method, path, _ = conexao.http_req.split(b' ', 2)
		print('Recebida requisição HTTP:', method, path)
		if path == b'/':
			send(fd, conexao, b'HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\nExperimente <a href="/arquivo">arquivo</a>')
			close(fd, conexao)
		elif path == b'/arquivo':
			send(fd, conexao, b'HTTP/1.0 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n' + 100000*b'repetido\n')
			close(fd, conexao)
		else:
			send(fd, conexao, b'HTTP/1.0 404 Not Found\r\n\r\nNot Found')
			close(fd, conexao)


def close(fd, conexao):
	send_segment(fd, conexao, make_fin(conexao))
	conexao.next_seq_no += 1


def send(fd, conexao, dados):

	conexao.send_queue += dados

	size_window = min(conexao.cwnd, conexao.rwnd)
	disponivel = max(size_window - len(conexao.no_ack_queue), 0)
	a_transmitir = conexao.send_queue[:disponivel]
	conexao.send_queue = conexao.send_queue[disponivel:]
	conexao.no_ack_queue += a_transmitir

	for i in range(0, len(a_transmitir), MSS):
		payload = a_transmitir[i:i+MSS]
		send_raw(fd, conexao, payload)

	print("========================= SAINDO ======================================\n")

	#Enviando dados pelo raw socket
def send_raw(fd, conexao, payload):

	#Conexao a ser enviado o pacote
	(dst_addr, dst_port, src_addr, src_port) = conexao.id_conexao

	print('send_raw called')

	#Montando pacote
	segment = struct.pack('!HHIIHHHH', src_port, dst_port, conexao.next_seq_no,
							conexao.ack_no, (5<<12)|FLAGS_ACK,
							1024, 0, 0) + payload

	#Pacote com checksum
	segment = fix_checksum(segment, src_addr, dst_addr)

	#Enviando
	fd.sendto(segment, (src_addr, src_port))

	#Adiciona timer se nao tiver
	if conexao.timer is None:
		#Reenvia o pacote caso o timer nao estiver desativado
		#conexao.timer = asyncio.get_event_loop().call_later(3, send_raw, fd, conexao, payload)
		print("Criei \n")

	#Adicionando current time do seq_no enviado
	conexao.dic_seq_no_curr_time[conexao.next_seq_no] = time.time()

	#Atualizando sequence number
	conexao.next_seq_no = (conexao.next_seq_no + len(payload)) & 0xffffffff

#Recebe novos dados do raw socket
def raw_recv(fd):
	#Recebe um pacote do socket
	packet = fd.recv(12000)

	#Tratamento do cabecalho da camada de rede
	src_addr, dst_addr, segment = handle_ipv4_header(packet)

	#Recupera informacões do pack
	#(Formato, porta fonte, porta destino, sequence number da conexao, ack number da conexao,
	# bit ACK, Window Size, CheckSum, Urg data pointer)
	src_port, dst_port, seq_no, ack_no, \
			flags, window_size, checksum, urg_ptr = \
			struct.unpack('!HHIIHHHH', segment[:20])

	#identificador da conexao
	id_conexao = (src_addr, src_port, dst_addr, dst_port)

	#Aceita somente a porta 7000
	if dst_port != 7000:
		return

	payload = segment[4*(flags>>12):]

	#Identificacao das flags
	#Conexao requerida e aceita
	if (flags & FLAGS_SYN) == FLAGS_SYN:
		#Verificar ack antes de criar objeto(?)
		conexao = abre_conexao(fd, id_conexao,seq_no)

	elif id_conexao in conexoes:
		conexao = conexoes[id_conexao]
		#conexao.ack_no += len(payload)

		if (flags & FLAGS_ACK) == FLAGS_ACK:
			#Recebe ack e tirar da fila de nao confirmados
			ack_recv(fd, conexao, ack_no)

		if (flags & FLAGS_FIN) == FLAGS_FIN:
			fin_recv(fd, conexao, seq_no)

		if (len(payload) != 0):
			#Recebe payload e envia pacote com ack e sem dados
			payload_recv(conexao, seq_no, payload)
			#Retorna dados para a aplicacao(?)
			#return payload
	#
	else:
		print('%s:%d -> %s:%d (pacote associado a conexao desconhecida)' %
		(src_addr, src_port, dst_addr, dst_port))


#Funcao principal
if __name__ == '__main__':
	fd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	loop = asyncio.get_event_loop()
	loop.add_reader(fd, raw_recv, fd)
	loop.run_forever()
