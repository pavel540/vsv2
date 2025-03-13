from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
from flask_bootstrap import Bootstrap5
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, URL
import docker
from scanner import VulnerabilityScanner
from urllib.parse import urlparse
import json
from datetime import datetime
import yaml
import os

# Загрузка конфигурации
config_path = '/etc/docker-vulnerability-scanner/config.yaml'
if os.path.exists(config_path):
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
else:
    config = {
        'web_interface': {
            'host': '0.0.0.0',
            'port': 5000,
            'secret_key': 'default-secret-key'
        }
    }

app = Flask(__name__,
           template_folder='/usr/lib/docker-vulnerability-scanner/templates')
app.config['SECRET_KEY'] = config['web_interface']['secret_key']
bootstrap = Bootstrap5(app)

class DockerHostForm(FlaskForm):
    host = StringField('Docker Host URL', validators=[DataRequired()],
                      default='tcp://localhost:2375',
                      description='Example: tcp://192.168.1.100:2375')
    submit = SubmitField('Подключиться')

@app.route('/')
def index():
    form = DockerHostForm()
    return render_template('index.html', form=form)

@app.route('/containers')
def list_containers():
    host = request.args.get('host', None)
    try:
        scanner = VulnerabilityScanner(docker_host=host)
        containers = scanner.docker_client.containers.list(all=True)
        
        containers_list = []
        for container in containers:
            containers_list.append({
                'id': container.short_id,
                'name': container.name,
                'image': container.image.tags[0] if container.image.tags else "none",
                'status': container.status,
                'host': f"{scanner.host_info.hostname}:{scanner.host_info.port}" if scanner.host_info else "локальный"
            })
        
        return render_template('containers.html', 
                             containers=containers_list,
                             host=host,
                             form=DockerHostForm())
    except Exception as e:
        flash(f'Ошибка при получении списка контейнеров: {str(e)}', 'danger')
        return redirect(url_for('index'))

@app.route('/scan/<container_id>')
def scan_container(container_id):
    host = request.args.get('host', None)
    try:
        scanner = VulnerabilityScanner(docker_host=host)
        
        # Получаем контейнер
        container = scanner.docker_client.containers.get(container_id)
        container_info = container.attrs
        
        # Формируем команду сканирования
        if scanner.host_info and scanner.host_info.hostname:
            image_path = f"{scanner.host_info.hostname}:{scanner.host_info.port}/{container_info['Config']['Image']}"
        else:
            image_path = container_info['Config']['Image']
            
        # Запускаем сканирование
        scan_results = scanner.scan_container(container_id)
        
        return render_template('scan_results.html',
                             container_id=container_id,
                             container_name=container.name,
                             image=image_path,
                             results=scan_results,
                             scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    except Exception as e:
        flash(f'Ошибка при сканировании контейнера: {str(e)}', 'danger')
        return redirect(url_for('list_containers', host=host))

@app.route('/check_host', methods=['POST'])
def check_host():
    host = request.form.get('host')
    try:
        parsed_url = urlparse(host)
        scanner = VulnerabilityScanner()
        if scanner.test_remote_connection(parsed_url.hostname, parsed_url.port or 2375):
            return jsonify({'status': 'success'})
        return jsonify({'status': 'error', 'message': 'Не удалось подключиться к хосту'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

if __name__ == '__main__':
    app.run(
        host=config['web_interface']['host'],
        port=config['web_interface']['port'],
        debug=False
    ) 