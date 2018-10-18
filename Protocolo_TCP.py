#!/usr/bin/python3
#
# Antes de usar, execute o seguinte comando para evitar que o Linux feche
# as conexões TCP abertas por este programa:
#
# sudo iptables -I OUTPUT -p tcp --tcp-flags RST RST -j DROP
#

import asyncio
import socket
import struct
import os
import random

FLAGS_FIN = 1<<0 #Flag de fim de conexão
FLAGS_SYN = 1<<1 #Flag de sicronização
FLAGS_RST = 1<<2 #Flag de warning socket não existente
FLAGS_ACK = 1<<4 #Flag de resposta ACK

MSS = 1460 #Maximum Segment Size

TESTAR_PERDA_ENVIO = False

#Anotações
#Send coloca na fila de envio, se fila estiver vazia já enviar. Depende da janela
conexoes = {}
class Conexao:
	def __init__(self, id_conexao, seq_no, ack_no):
		self.id_conexao = id_conexao
		self.ack_no = ack_no

		self.send_base = seq_no
		self.nextSeq_no = seq_no

		self.send_queue = b""
		self.noAck_queue = b""
		
		self.cwnd = self.rwnd = 10*MSS

		self.timer = None




#Converte endereço para string
def addr2str(addr):
	return '%d.%d.%d.%d' % tuple(int(x) for x in addr)

#Converte string para endereço
def str2addr(addr):
	return bytes(int(x) for x in addr.split('.'))

#Cabeçalho da camada de rede - IP Datagram Format 
def handle_ipv4_header(packet):
	#Versão do procotolo IP
	version = packet[0] >> 4
	#Tamanho do Cabeçalho
	ihl = packet[0] & 0xf
	#Verifica se a versão do IP é a 4
	assert version == 4
	#Endereço fonte
	src_addr = addr2str(packet[12:16])
	#Endereço destino
	dst_addr = addr2str(packet[16:20])
	#Segmento contendo o protocolo TCP
	segment = packet[4*ihl:]

	return src_addr, dst_addr, segment

#Aceita conexão - Syn + ACK
def make_synack(src_port, dst_port, seq_no, ack_no):
	#Monta pacote a ser enviado
	#(Formato dos dados, porta fonte, porta destino, Sequence Number, ACK Number,bit ACK e bit SYN, 
	# Window Size, CheckSum, Urg data pointer)
	return struct.pack('!HHIIHHHH', src_port, dst_port, seq_no,ack_no, (5<<12)|FLAGS_ACK|FLAGS_SYN,
                       1024, 0, 0)

#Rejeita conexão - RST - Porta não disponivel
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
	#Conversão para Byte
	seg = bytearray(segment)
	#
	seg[16:18] = b'\x00\x00'
	#
	seg[16:18] = struct.pack('!H', calc_checksum(pseudohdr + seg))
	
	return bytes(seg)

#Gerencia fila de envio
def send_next(fd, conexao):
	#Obtem segmento da fila
	payload = conexao.send_queue[:MSS]
	
	#Remove o segmento da fila
	conexao.send_queue = conexao.send_queue[MSS:]
	
	#Obtem informações da conexão
	(dst_addr, dst_port, src_addr, src_port) = conexao.id_conexao
	
	#Monta segmento para envio
	#(Formato, porta fonte, porta destino, sequence number da conexão, ack number da conexão, 
	# bit ACK, Window Size, CheckSum, Urg data pointer) + dados obtidos da fila de envio
	segment = struct.pack('!HHIIHHHH', src_port, dst_port, conexao.seq_no,
                          conexao.ack_no, (5<<12)|FLAGS_ACK,
                          1024, 0, 0) + payload
	
	#Geração do novo sequence number
	conexao.seq_no = (conexao.seq_no + len(payload)) & 0xffffffff
	
	#Segmento com checksum
	segment = fix_checksum(segment, src_addr, dst_addr)

	#
	if not TESTAR_PERDA_ENVIO or random.random() < 0.95:
		fd.sendto(segment, (dst_addr, dst_port))
	#Finaliza conexão
	if conexao.send_queue == b"":
		segment = struct.pack('!HHIIHHHH', src_port, dst_port, conexao.seq_no,
                          conexao.ack_no, (5<<12)|FLAGS_FIN|FLAGS_ACK,
                          0, 0, 0)
		segment = fix_checksum(segment, src_addr, dst_addr)
		fd.sendto(segment, (dst_addr, dst_port))
	#Chama novamente o envio de um novo segmento presente na fila
	else:
		asyncio.get_event_loop().call_later(.001, send_next, fd, conexao)


def ack_recv():
	return

def payload_recv():
	return

def send(fd, conexao, dados):
	
	conexao.send_queue += dados
	
	size_window = min(conexao.cwnd, conexao.rwnd)
	disponivel = max(size_window - len(conexao.noAck_queue), 0)
	a_transmitir = conexao.send_queue[:disponivel]
	noAck_queue += a_transmitir

	for i in range(0, len(a_transmitir), MSS):
		payload = a_transmitir[i:i+MSS]
		#Envia payload
	
	return 0

def abre_conexao(fd, id_conexao):
	(src_addr, src_port, dst_addr, dst_port) = id_conexao
	
	print('%s:%d -> %s:%d (seq=%d)' % (src_addr, src_port,
                                           dst_addr, dst_port, seq_no))

		#Alocando nova conexão
		conexoes[id_conexao] = conexao = Conexao(id_conexao=id_conexao,
	                                                 seq_no=struct.unpack('I', os.urandom(4))[0],
	                                                 ack_no=seq_no + 1)
	
		fd.sendto(fix_checksum(make_synack(dst_port, src_port, conexao.seq_no, conexao.ack_no),
	                           src_addr, dst_addr),
	              (src_addr, src_port))
				  
		conexao.nextSeq_no += 1
		
	return conexao
	
#Recebe novos dados do raw socket
def raw_recv(fd):
	#Recebe um pacote do socket
	packet = fd.recv(12000)
	
	#Tratamento do cabeçalho da camada de rede
	src_addr, dst_addr, segment = handle_ipv4_header(packet)
	
	#Recupera informações do pack
	#(Formato, porta fonte, porta destino, sequence number da conexão, ack number da conexão, 
	# bit ACK, Window Size, CheckSum, Urg data pointer)
	src_port, dst_port, seq_no, ack_no, \
        	flags, window_size, checksum, urg_ptr = \
        	struct.unpack('!HHIIHHHH', segment[:20])
	
	#identificador da conexão
	id_conexao = (src_addr, src_port, dst_addr, dst_port)
	
	#Aceita somente a porta 7000
	if dst_port != 7000:
		return
		#segment = struct.pack('!HHIIHHHH', src_port, dst_port, struct.unpack('I', os.urandom(4))[0] ,
        #                  seq_no + 1, (5<<12)|FLAGS_RST,
        #                  0, 0, 0)
		#segment = fix_checksum(segment, src_addr, dst_addr)
		#fd.sendto(segment, (dst_addr, dst_port))
		
	#
	#print(segment.decode())
	payload = segment[4*(flags>>12):]
	#Identificação das flags
	#Conexão requerida e aceita
	if (flags & FLAGS_SYN) == FLAGS_SYN:
		conexao = abre_conexao(fd, id_conexao)

		#asyncio.get_event_loop().call_later(.1, send_next, fd, conexao
	
	elif id_conexao in conexoes:
		conexao = conexoes[id_conexao]
		conexao.ack_no += len(payload)
		
		if (flags & FLAGS_ACK) == FLAGS_ACK:
		ack_recv()
	
		if (len(payload) != 0):
		payload_recv()
	#
	else:
		print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
		(src_addr, src_port, dst_addr, dst_port))


#Função principal
if __name__ == '__main__':
	fd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	loop = asyncio.get_event_loop()
	loop.add_reader(fd, raw_recv, fd)
	loop.run_forever()
