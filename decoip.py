import random
import time
from scapy.all import IP, TCP, sr1, send  # Убедитесь, что scapy установлен

def random_ip():
    """Генерирует случайный IP-адрес"""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

def send_packets(target_ip, real_src_ip, target_ports=None, fake_src_ips=None, num_random_ips=0, num_requests=1, requests_per_minute=12000):
    """Отправляет пакеты на заданный IP-адрес"""
    if target_ports is None:
        target_ports = range(0, 65536)

    if target_ports == []:
        return

    if not fake_src_ips:
        fake_src_ips = [random_ip() for _ in range(num_random_ips)]
    
    open_ports = []
    
    # Рассчитываем время ожидания между запросами
    interval = 60 / requests_per_minute  # время ожидания в секундах

    # Перемешиваем порты для случайного перебора
    target_ports = list(target_ports)
    random.shuffle(target_ports)

    for port in target_ports:
        real_syn_packet = IP(dst=target_ip, src=real_src_ip) / TCP(dport=port, flags='S')
        real_response = sr1(real_syn_packet, timeout=2, verbose=0)

        if real_response and real_response.haslayer(TCP):
            tcp_layer = real_response.getlayer(TCP)
            if tcp_layer.flags == 0x12:  # Если пришел SYN-ACK
                rst_packet = IP(dst=target_ip, src=real_src_ip) / TCP(dport=port, sport=tcp_layer.dport, flags='R')
                send(rst_packet, verbose=0)  # Отправляем RST, чтобы закрыть соединение
                open_ports.append(port)
                print(f"Порт {port} на {target_ip} открыт.")
        
        for fake_src_ip in fake_src_ips:
            for _ in range(num_requests):
                fake_syn_packet = IP(dst=target_ip, src=fake_src_ip) / TCP(dport=port, flags='S')
                send(fake_syn_packet, verbose=0)
                
                # Ожидаем случайное время между запросами
                time.sleep(interval + random.uniform(0, interval))  # добавление случайного времени от 0 до интервала

        # Ожидание между перебором портов
        time.sleep(random.uniform(0, interval))  # случайное время между обращениями к портам


# Пример вызова функции только с обязательными аргументами:
target_ip = '192.168.1.2'
real_src_ip = '192.168.1.3'

# Пример вызова функции с необязательными аргументами:
target_ports = [22, 80, 443]
fake_src_ips = ['192.168.2.2', '192.144.2.12']
num_random_ips = 5
num_requests = 3

send_packets(target_ip, real_src_ip, target_ports=target_ports, num_random_ips=num_random_ips)
