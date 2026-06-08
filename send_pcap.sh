#!/bin/bash

# 定义颜色代码
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

check_file_exists() {
local filename="$1"
while [ -e "$filename" ]; do
sleep 0.001
done
}

# 定义回放单个文件的函数
replay_file() {
local file="$1"
local target_dir="$2"
local replay_count="$3"
local quiet_mode="$4"
local file_name=$(basename "$1")
echo -e "${GREEN}Replaying file: $file${NC}"
if [ "$quiet_mode" = true ]; then
target_file="${target_dir}/${file_name}"
else
target_file="${target_dir}/${file_name}.osp"
fi
cp -rf "$file" "$target_file"
echo -e "${GREEN}Replaying target file: $target_file${NC}"
check_file_exists "$target_file"
return 0
}

# 定义遍历目录并回放所有报文的函数
replay_directory() {
local dir="$1"
local dpi_pcap_dir="$2"
local replay_count="$3"
local quiet_mode="$4"

for file in "$dir"/*.{pcap,cap,pcapng}; do
[ -f "$file" ] || continue # 跳过非文件或隐藏文件
replay_file "$file" "$dpi_pcap_dir" "$replay_count" "$quiet_mode"
done
}

# 定义递归遍历目录并回放所有报文的函数
replay_recursive_directory() {
local dir="$1"
local dpi_pcap_dir="$2"
local replay_count="$3"
local quiet_mode="$4"

find "$dir" -type f \( -name "*.pcap" -o -name "*.cap" -o -name "*.pcapng" \) | while read -r file; do
replay_file "$file" "$dpi_pcap_dir" "$replay_count" "$quiet_mode"
done
}

# 初始化参数
input=""
dpi_pcap_dir="/home/updpi/pcap_dir"
replay_count=1
quiet_mode=false

# 解析参数
while getopts ":q" opt; do
case $opt in
q)
quiet_mode=true
;;
\?)
echo -e "${RED}Invalid option: -$OPTARG${NC}" >&2
exit 1
;;
esac
done

# 移除已解析的选项参数
shift $((OPTIND -1))

# 检查是否提供了至少两个参数
if [ $# -lt 1 ]; then
echo -e "${YELLOW}Usage: $0 [-q] <file_or_directory> <target_directory> [<replay_count>]${NC}"
exit 1
fi

# 获取参数
input="$1"

if [ $# -ge 2 ]; then
dpi_pcap_dir="$2"
fi

if [ $# -ge 3 ]; then
replay_count="$3"
fi

# 验证 replay_count 是否为非负整数
if ! [[ "$replay_count" =~ ^[0-9]+$ ]]; then
echo -e "${RED}Error: replay_count must be a non-negative integer.${NC}"
exit 1
fi
count=0
if [ "$replay_count" -eq 0 ]; then
# 循环回放，直到手动中断
while true; do
if [ -f "$input" ]; then
# 参数1为文件，直接回放单个文件
replay_file "$input" "$dpi_pcap_dir" "$replay_count" "$quiet_mode"
elif [ -d "$input" ]; then
# 参数1为目录，遍历目录并回放所有报文
replay_recursive_directory "$input" "$dpi_pcap_dir" "$replay_count" "$quiet_mode"
else
echo -e "${RED}Error: First argument must be a file or directory.${NC}"
exit 1
fi
((count+=1))
echo -e "${YELLOW} [$count] $input >> $dpi_pcap_dir ${NC}"
sleep 10
done
else
for ((i = 0; i < replay_count; i++)); do
if [ -f "$input" ]; then
# 参数1为文件，直接回放单个文件
replay_file "$input" "$dpi_pcap_dir" "$replay_count" "$quiet_mode"
elif [ -d "$input" ]; then
# 参数1为目录，遍历目录并回放所有报文
replay_recursive_directory "$input" "$dpi_pcap_dir" "$replay_count" "$quiet_mode"
else
echo -e "${RED}Error: First argument must be a file or directory.${NC}"
exit 1
fi
done
fi

exit 0