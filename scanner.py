#!/usr/bin/env python3

import click
import docker
import json
import sys
from rich.console import Console
from rich.table import Table
from datetime import datetime
import subprocess
import yaml
import socket
from urllib.parse import urlparse
import re
import os
import tempfile
import shutil

console = Console()

class VulnerabilityScanner:
    def __init__(self, docker_host=None):
        """
        Инициализация сканера
        :param docker_host: URL удаленного Docker хоста (например, tcp://192.168.1.100:2375)
        """
        try:
            if docker_host:
                self.docker_client = docker.DockerClient(base_url=docker_host)
                self.host_info = urlparse(docker_host)
            else:
                self.docker_client = docker.from_env()
                self.host_info = None
        except docker.errors.DockerException as e:
            console.print(f"[red]Ошибка подключения к Docker: {str(e)}[/red]")
            sys.exit(1)
        
    def check_astra_compatibility(self):
        """Проверка совместимости с Астра Линукс 1.7.6"""
        try:
            with open('/etc/os-release', 'r') as f:
                os_info = f.read()
                if 'Astra Linux 1.7.6' not in os_info:
                    console.print("[yellow]Предупреждение: Система не определена как Астра Линукс 1.7.6[/yellow]")
                    return False
        except FileNotFoundError:
            console.print("[red]Ошибка: Невозможно определить версию ОС[/red]")
            return False
        return True

    def test_remote_connection(self, host, port):
        """Проверка доступности удаленного Docker хоста"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def analyze_dockerfile(self, dockerfile_content):
        """Анализ Dockerfile на наличие проблем безопасности"""
        issues = []
        
        # Проверка использования root пользователя
        if 'USER root' in dockerfile_content:
            issues.append({
                'type': 'dockerfile',
                'severity': 'HIGH',
                'description': 'Использование root пользователя может быть небезопасным',
                'recommendation': 'Используйте непривилегированного пользователя'
            })
        
        # Проверка использования последних версий базовых образов
        base_image_match = re.search(r'FROM\s+(\S+)(?::\S+)?', dockerfile_content)
        if base_image_match and ':latest' in base_image_match.group(0):
            issues.append({
                'type': 'dockerfile',
                'severity': 'MEDIUM',
                'description': 'Использование тега :latest может привести к непредсказуемым результатам',
                'recommendation': 'Укажите конкретную версию базового образа'
            })
        
        # Проверка наличия HEALTHCHECK
        if 'HEALTHCHECK' not in dockerfile_content:
            issues.append({
                'type': 'dockerfile',
                'severity': 'LOW',
                'description': 'Отсутствует HEALTHCHECK',
                'recommendation': 'Добавьте HEALTHCHECK для мониторинга состояния контейнера'
            })
        
        return issues

    def scan_dependencies(self, container_id):
        """Сканирование зависимостей в контейнере"""
        try:
            container = self.docker_client.containers.get(container_id)
            
            # Создаем временную директорию для копирования файлов
            with tempfile.TemporaryDirectory() as temp_dir:
                # Проверяем наличие различных файлов зависимостей
                dependency_files = [
                    '/app/requirements.txt',
                    '/app/package.json',
                    '/app/composer.json',
                    '/app/Gemfile'
                ]
                
                dependencies = []
                
                for dep_file in dependency_files:
                    try:
                        # Копируем файл из контейнера
                        bits, stat = container.get_archive(dep_file)
                        with open(os.path.join(temp_dir, 'dep_file'), 'wb') as f:
                            for chunk in bits:
                                f.write(chunk)
                        
                        # Анализируем файл зависимостей
                        with open(os.path.join(temp_dir, 'dep_file'), 'r') as f:
                            content = f.read()
                            
                            if dep_file.endswith('requirements.txt'):
                                # Анализ Python зависимостей
                                for line in content.splitlines():
                                    if line and not line.startswith('#'):
                                        pkg = line.split('==')[0] if '==' in line else line
                                        dependencies.append({
                                            'type': 'python',
                                            'package': pkg,
                                            'source': 'requirements.txt'
                                        })
                            
                            elif dep_file.endswith('package.json'):
                                # Анализ Node.js зависимостей
                                pkg_json = json.loads(content)
                                for pkg, version in pkg_json.get('dependencies', {}).items():
                                    dependencies.append({
                                        'type': 'nodejs',
                                        'package': pkg,
                                        'version': version,
                                        'source': 'package.json'
                                    })
                    
                    except Exception:
                        continue
                
                return dependencies
        
        except Exception as e:
            console.print(f"[red]Ошибка при сканировании зависимостей: {str(e)}[/red]")
            return []

    def scan_os_vulnerabilities(self, image_id):
        """Сканирование уязвимостей операционной системы"""
        try:
            # Запуск Trivy для сканирования ОС
            cmd = f"trivy image --severity HIGH,CRITICAL --vuln-type os {image_id}"
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = process.communicate()
            
            if process.returncode != 0:
                console.print(f"[red]Ошибка при сканировании ОС: {error.decode()}[/red]")
                return []
            
            return self.parse_trivy_output(output.decode())
        
        except Exception as e:
            console.print(f"[red]Ошибка при сканировании ОС: {str(e)}[/red]")
            return []

    def scan_software_vulnerabilities(self, image_id):
        """Сканирование уязвимостей установленного ПО"""
        try:
            # Запуск Trivy для сканирования ПО
            cmd = f"trivy image --severity HIGH,CRITICAL --vuln-type library {image_id}"
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = process.communicate()
            
            if process.returncode != 0:
                console.print(f"[red]Ошибка при сканировании ПО: {error.decode()}[/red]")
                return []
            
            return self.parse_trivy_output(output.decode())
        
        except Exception as e:
            console.print(f"[red]Ошибка при сканировании ПО: {str(e)}[/red]")
            return []

    def get_dockerfile_content(self, container_id):
        """Получение содержимого Dockerfile из контейнера"""
        try:
            container = self.docker_client.containers.get(container_id)
            image_id = container.image.id
            
            # Попытка получить историю образа
            image = self.docker_client.images.get(image_id)
            history = image.history()
            
            # Реконструкция Dockerfile из истории
            dockerfile_content = []
            for layer in history:
                cmd = layer.get('CreatedBy', '')
                if cmd:
                    # Очистка команды
                    cmd = cmd.replace('/bin/sh -c #(nop) ', '')
                    cmd = cmd.replace('/bin/sh -c', 'RUN')
                    dockerfile_content.append(cmd)
            
            return '\n'.join(reversed(dockerfile_content))
        
        except Exception as e:
            console.print(f"[red]Ошибка при получении Dockerfile: {str(e)}[/red]")
            return None

    def scan_container(self, container_id_or_name):
        """Сканирование указанного контейнера"""
        try:
            container = self.docker_client.containers.get(container_id_or_name)
            container_info = container.attrs
            image_id = container_info['Config']['Image']
            
            scan_results = {
                'os_vulnerabilities': [],
                'software_vulnerabilities': [],
                'dependencies': [],
                'dockerfile_issues': [],
                'general_info': {
                    'container_id': container.short_id,
                    'image_id': image_id,
                    'created': container_info['Created'],
                    'status': container_info['State']['Status']
                }
            }
            
            # Сканирование уязвимостей ОС
            console.print("[yellow]Сканирование уязвимостей операционной системы...[/yellow]")
            scan_results['os_vulnerabilities'] = self.scan_os_vulnerabilities(image_id)
            
            # Сканирование уязвимостей ПО
            console.print("[yellow]Сканирование уязвимостей программного обеспечения...[/yellow]")
            scan_results['software_vulnerabilities'] = self.scan_software_vulnerabilities(image_id)
            
            # Анализ зависимостей
            console.print("[yellow]Анализ зависимостей...[/yellow]")
            scan_results['dependencies'] = self.scan_dependencies(container.id)
            
            # Анализ Dockerfile
            console.print("[yellow]Анализ Dockerfile...[/yellow]")
            dockerfile_content = self.get_dockerfile_content(container.id)
            if dockerfile_content:
                scan_results['dockerfile_issues'] = self.analyze_dockerfile(dockerfile_content)
            
            return scan_results
            
        except docker.errors.NotFound:
            console.print("[red]Ошибка: Контейнер не найден[/red]")
            return None
        except Exception as e:
            console.print(f"[red]Ошибка: {str(e)}[/red]")
            return None

    def parse_trivy_output(self, output):
        """Парсинг вывода Trivy в структурированный формат"""
        vulnerabilities = []
        current_vuln = {}
        
        # Регулярные выражения для парсинга
        vuln_pattern = re.compile(r'([A-Z]+-\d+)\s+(\w+)\s+(.+?)\s+(\d+\.\d+|\?)\s*$')
        fixed_version_pattern = re.compile(r'Fixed-In:\s+(.+)$')
        
        for line in output.split('\n'):
            line = line.strip()
            
            # Поиск информации о уязвимости
            vuln_match = vuln_pattern.match(line)
            if vuln_match:
                if current_vuln:
                    vulnerabilities.append(current_vuln)
                
                current_vuln = {
                    'id': vuln_match.group(1),
                    'severity': vuln_match.group(2),
                    'description': vuln_match.group(3),
                    'cvss_score': vuln_match.group(4),
                    'fixed_version': 'Not available'
                }
                continue
            
            # Поиск информации о исправленной версии
            fixed_match = fixed_version_pattern.match(line)
            if fixed_match and current_vuln:
                current_vuln['fixed_version'] = fixed_match.group(1)
        
        if current_vuln:
            vulnerabilities.append(current_vuln)
        
        return vulnerabilities

    def list_containers(self):
        """Вывод списка доступных контейнеров"""
        try:
            containers = self.docker_client.containers.list(all=True)
            
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("ID")
            table.add_column("Имя")
            table.add_column("Образ")
            table.add_column("Статус")
            table.add_column("Хост")
            
            host_info = f"{self.host_info.hostname}:{self.host_info.port}" if self.host_info else "локальный"
            
            for container in containers:
                table.add_row(
                    container.short_id,
                    container.name,
                    container.image.tags[0] if container.image.tags else "none",
                    container.status,
                    host_info
                )
            
            console.print(table)
        except Exception as e:
            console.print(f"[red]Ошибка при получении списка контейнеров: {str(e)}[/red]")

    def _display_results(self, scan_results):
        """Отображение результатов сканирования"""
        if not scan_results:
            console.print("[red]Нет результатов сканирования[/red]")
            return

        # Общая информация
        console.print("\n[bold blue]Общая информация о контейнере:[/bold blue]")
        info_table = Table(show_header=True)
        info_table.add_column("Параметр")
        info_table.add_column("Значение")
        for key, value in scan_results['general_info'].items():
            info_table.add_row(key, str(value))
        console.print(info_table)

        # Уязвимости ОС
        console.print("\n[bold red]Уязвимости операционной системы:[/bold red]")
        if scan_results['os_vulnerabilities']:
            self._display_vulnerability_table(scan_results['os_vulnerabilities'])
        else:
            console.print("[green]Уязвимостей не обнаружено[/green]")

        # Уязвимости ПО
        console.print("\n[bold red]Уязвимости программного обеспечения:[/bold red]")
        if scan_results['software_vulnerabilities']:
            self._display_vulnerability_table(scan_results['software_vulnerabilities'])
        else:
            console.print("[green]Уязвимостей не обнаружено[/green]")

        # Зависимости
        console.print("\n[bold yellow]Зависимости:[/bold yellow]")
        if scan_results['dependencies']:
            dep_table = Table(show_header=True)
            dep_table.add_column("Тип")
            dep_table.add_column("Пакет")
            dep_table.add_column("Версия")
            dep_table.add_column("Источник")
            for dep in scan_results['dependencies']:
                dep_table.add_row(
                    dep['type'],
                    dep['package'],
                    dep.get('version', 'N/A'),
                    dep['source']
                )
            console.print(dep_table)
        else:
            console.print("[yellow]Зависимости не обнаружены[/yellow]")

        # Проблемы в Dockerfile
        console.print("\n[bold yellow]Проблемы в Dockerfile:[/bold yellow]")
        if scan_results['dockerfile_issues']:
            dockerfile_table = Table(show_header=True)
            dockerfile_table.add_column("Серьезность")
            dockerfile_table.add_column("Описание")
            dockerfile_table.add_column("Рекомендация")
            for issue in scan_results['dockerfile_issues']:
                dockerfile_table.add_row(
                    issue['severity'],
                    issue['description'],
                    issue['recommendation']
                )
            console.print(dockerfile_table)
        else:
            console.print("[green]Проблем не обнаружено[/green]")

    def _display_vulnerability_table(self, vulnerabilities):
        """Отображение таблицы уязвимостей"""
        table = Table(show_header=True)
        table.add_column("ID")
        table.add_column("Серьезность")
        table.add_column("Описание")
        table.add_column("CVSS")
        table.add_column("Исправлено в версии")
        
        for vuln in vulnerabilities:
            table.add_row(
                vuln['id'],
                vuln['severity'],
                vuln['description'],
                vuln['cvss_score'],
                vuln['fixed_version']
            )
        
        console.print(table)

@click.group()
def cli():
    """Сканер уязвимостей Docker контейнеров для Астра Линукс 1.7.6"""
    pass

@cli.command()
@click.argument('container_id', required=False)
@click.option('--host', '-h', help='URL удаленного Docker хоста (например, tcp://192.168.1.100:2375)')
def scan(container_id, host):
    """Сканировать указанный контейнер на наличие уязвимостей"""
    scanner = VulnerabilityScanner(docker_host=host)
    
    if not scanner.check_astra_compatibility():
        if not click.confirm("Продолжить сканирование?"):
            return
    
    # Проверка подключения к удаленному хосту
    if host:
        parsed_url = urlparse(host)
        if not scanner.test_remote_connection(parsed_url.hostname, parsed_url.port or 2375):
            console.print(f"[red]Ошибка: Не удалось подключиться к удаленному хосту {host}[/red]")
            return
    
    if container_id:
        results = scanner.scan_container(container_id)
        if results:
            scanner._display_results(results)
    else:
        console.print("[yellow]Список доступных контейнеров:[/yellow]")
        scanner.list_containers()
        container_id = click.prompt("Введите ID контейнера для сканирования")
        results = scanner.scan_container(container_id)
        if results:
            scanner._display_results(results)

@cli.command()
@click.option('--host', '-h', help='URL удаленного Docker хоста (например, tcp://192.168.1.100:2375)')
def list(host):
    """Показать список доступных контейнеров"""
    scanner = VulnerabilityScanner(docker_host=host)
    scanner.list_containers()

if __name__ == '__main__':
    cli() 