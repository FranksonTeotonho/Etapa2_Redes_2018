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
FLAGS_SYN = 1<<1 #Flag de sicronizaçao
FLAGS_RST = 1<<2 #Flag de warning socket nao existente
FLAGS_ACK = 1<<4 #Flag de resposta ACK

MSS = 1460 #Maximum Segment Size

TESTAR_PERDA_ENVIO = False

#Anotações
#Send coloca na fila de envio, se fila estiver vazia já enviar. Depende da janela
conexoes = {}
class Conexao:
	def __init__(self, id_conexao, seq_no, ack_no):
		#Informações para a conexao
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
		#Flag para timer ativo
		self.flag_timer_active = False
		#Flag handshake
		self.flag_handshake = True


#Converte endereço para string
def addr2str(addr):
	return '%d.%d.%d.%d' % tuple(int(x) for x in addr)

#Converte string para endereço
def str2addr(addr):
	return bytes(int(x) for x in addr.split('.'))

#Cabeçalho da camada de rede - IP Datagram Format 
def handle_ipv4_header(packet):
	#Versao do procotolo IP
	version = packet[0] >> 4
	#Tamanho do Cabeçalho
	ihl = packet[0] & 0xf
	#Verifica se a versao do IP é a 4
	assert version == 4
	#Endereço fonte
	src_addr = addr2str(packet[12:16])
	#Endereço destino
	dst_addr = addr2str(packet[16:20])
	#Segmento contendo o protocolo TCP
	segment = packet[4*ihl:]

	return src_addr, dst_addr, segment

#Aceita conexao - Syn + ACK
def make_synack(src_port, dst_port, seq_no, ack_no):
	#Monta pacote a ser enviado
	#(Formato dos dados, porta fonte, porta destino, Sequence Number, ACK Number,bit ACK e bit SYN, 
	# Window Size, CheckSum, Urg data pointer)
	return struct.pack('!HHIIHHHH', src_port, dst_port, seq_no,ack_no, (5<<12)|FLAGS_ACK|FLAGS_SYN,
						1024, 0, 0)

#Rejeita conexao - RST - Porta nao disponivel
def make_rst(src_port, dst_port, seq_no, ack_no):
	#Monta pacote a ser enviado
	#(Formato dos dados, porta fonte, porta destino, Sequence Number, ACK Number,bit RST, 
	# Window Size, CheckSum, Urg data pointer)
	return struct.pack('!HHIIHHHH', src_port, dst_port, seq_no,ack_no, (5<<12)|FLAGS_RST,
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
	#Pseudo cabeçalho
	#Endereço Fonte + Endereço Destino + (formato, Identificador TCP, Tamanho do segmento)
	pseudohdr = str2addr(src_addr) + str2addr(dst_addr) + struct.pack('!HH', 0x0006, len(segment))
	#Conversao para Byte
	seg = bytearray(segment)
	#
	seg[16:18] = b'\x00\x00'
	#
	seg[16:18] = struct.pack('!H', calc_checksum(pseudohdr + seg))

	return bytes(seg)

#Separar funçao(?)
def abre_conexao(fd, id_conexao,seq_no):
	(src_addr, src_port, dst_addr, dst_port) = id_conexao

	print('%s:%d -> %s:%d (seq=%d)' % (src_addr, src_port,
											dst_addr, dst_port,seq_no))

		#Alocando nova conexao
	conexoes[id_conexao] = conexao = Conexao(id_conexao=id_conexao,
														seq_no=struct.unpack('I', os.urandom(4))[0],
														ack_no=seq_no + 1)

	fd.sendto(fix_checksum(make_synack(dst_port, src_port, conexao.next_seq_no, conexao.ack_no),
								src_addr, dst_addr),
					(src_addr, src_port))
					
	conexao.next_seq_no += 1
		
	return conexao


#Trata recebimento do ack_no
def ack_recv(conexao, ack_no):
	if(ack_no > conexao.send_base):
		#Handshake, nenhum dado presente nas filas
		#Duvidas... o que fzr
		if(conexao.flag_handshake == True):
			conexao.send_base = ack_no
			conexao.flag_handshake = False
		#Situaçao onde a conexao já esta estabelecida
		else:
			#Dados confirmados a serem removidos da noAck_
			qtd_dados_reconhecidos = ack_no - conexao.send_base - 1 
			#Atualiza send_base
			conexao.send_base = ack_no
			
			#Para timer do ultimo pacote sem resposta ack 
			conexao.timer.cancel()
			conexao.flag_timer_active = ~(conexao.timer.cancelled())

			#Remove da fila de enviados sem confirmaçao
			conexao.no_ack_queue = conexao.no_ack_queue[qtd_dados_reconhecidos:]

			#No caso de haver mais pacotes ainda sem resposta ack, start time para o ultimo deles
			if(conexao.no_ack_queue != b''):
				print("if vazio")
				#Adicionar novo timer
				#Usar dicionario
				#Como referenciar o pacote e fazer callback?
	return



	#Trata recebimento de payload
def payload_recv(conexao, seq_no):
	print("ta em shokk!?")
	return

def send(fd, conexao, dados):

	conexao.send_queue += dados

	size_window = min(conexao.cwnd, conexao.rwnd)
	disponivel = max(size_window - len(conexao.no_ack_queue), 0)
	a_transmitir = conexao.send_queue[:disponivel]
	conexao.no_ack_queue += a_transmitir

	for i in range(0, len(a_transmitir), MSS):
		payload = a_transmitir[i:i+MSS]
		send_raw(fd, conexao, payload)


	#Enviando dados pelo raw socket
def send_raw(fd, conexao, payload):

	#Conexao a ser enviado o pacote
	(dst_addr, dst_port, src_addr, src_port) = conexao.id_conexao

	#Montando pacote
	segment = struct.pack('!HHIIHHHH', src_port, dst_port, conexao.next_seq_no,
							conexao.ack_no, (5<<12)|FLAGS_ACK,
							1024, 0, 0) + payload

	#Pacote com checksum
	segment = fix_checksum(segment, src_addr, dst_addr)

	#Enviando
	fd.sendto(Segment, (src_addr, src_port))

	#Adiciona timer se nao tiver
	if(conexao.flag_timer_active == False):
		#Reenvia o pacote caso o timer nao estiver desativado
		conexao.timer = asyncio.get_event_loop().call_later(.001, send_raw, fd, conexao, payload)
		conexao.flag_timer_active = True

	#Adicionando current time do seq_no enviado
	conexao.dic_seq_no_curr_time[conexao.next_seq_no] = time.time()

	#Atualizando sequence number
	conexao.next_seq_no = (conexao.next_seq_no + len(payload)) & 0xffffffff

#Recebe novos dados do raw socket
def raw_recv(fd):
	#Recebe um pacote do socket
	packet = fd.recv(12000)

	#Tratamento do cabeçalho da camada de rede
	src_addr, dst_addr, segment = handle_ipv4_header(packet)

	#Recupera informações do pack
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

	#Identificaçao das flags
	#Conexao requerida e aceita
	if (flags & FLAGS_SYN) == FLAGS_SYN:
		#Verificar ack antes de criar objeto(?)
		conexao = abre_conexao(fd, id_conexao,seq_no)

	elif id_conexao in conexoes:
		conexao = conexoes[id_conexao]
		conexao.ack_no += len(payload)
		
		if (flags & FLAGS_ACK) == FLAGS_ACK:
			#Recebe ack e tirar da fila de nao confirmados
			ack_recv(conexao, ack_no)

		if (len(payload) != 0):
			#Recebe payload e envia pacote com ack e sem dados
			payload_recv(conexao, seq_no)
			#Retorna dados para a aplicaçao(?)
			#return payload
	#
	else:
		print('%s:%d -> %s:%d (pacote associado a conexao desconhecida)' %
		(src_addr, src_port, dst_addr, dst_port))


#Funçao principal
if __name__ == '__main__':
	fd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	loop = asyncio.get_event_loop()
	loop.add_reader(fd, raw_recv, fd)
	loop.run_forever()
