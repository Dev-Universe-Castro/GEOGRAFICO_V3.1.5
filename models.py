from app import db
from datetime import datetime

class CropData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    municipality_code = db.Column(db.String(10), nullable=False)
    municipality_name = db.Column(db.String(100), nullable=False)
    state_code = db.Column(db.String(2), nullable=False)
    crop_name = db.Column(db.String(100), nullable=False)
    harvested_area = db.Column(db.Float, nullable=False)
    year = db.Column(db.Integer, nullable=False, default=2023)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<CropData {self.municipality_name} - {self.crop_name}>'

class ProcessingLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    records_processed = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text)
    processed_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ProcessingLog {self.filename} - {self.status}>'

class Revenda(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(200), nullable=False)
    cnpj = db.Column(db.String(18), nullable=False, unique=True)
    cnae = db.Column(db.String(10), nullable=False)
    municipios = db.Column(db.Text, nullable=False)  # JSON string com lista de códigos de municípios
    cor = db.Column(db.String(7), nullable=False, default='#4CAF50')  # Cor hex para visualização
    ativo = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<Revenda {self.nome}>'

    def get_municipios_list(self):
        """Retorna lista de códigos de municípios"""
        import json
        try:
            return json.loads(self.municipios) if self.municipios else []
        except:
            return []

    def set_municipios_list(self, municipios_list):
        """Define lista de códigos de municípios"""
        import json
        self.municipios = json.dumps(municipios_list)

class Vendedor(db.Model):
    __tablename__ = 'vendedor'
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    telefone = db.Column(db.String(20), nullable=False)
    cpf = db.Column(db.String(14), nullable=False, unique=True)
    municipios = db.Column(db.Text, nullable=False)  # JSON string com lista de códigos de municípios
    cor = db.Column(db.String(7), nullable=False, default='#2196F3')  # Cor hex para visualização
    ativo = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<Vendedor {self.nome}>'

    def get_municipios_list(self):
        """Retorna lista de códigos de municípios"""
        import json
        try:
            return json.loads(self.municipios) if self.municipios else []
        except json.JSONDecodeError:
            print(f"Error decoding JSON for vendedor ID {self.id}. Municipios data: {self.municipios}")
            return []

    def set_municipios_list(self, municipios_list):
        """Define lista de códigos de municípios"""
        import json
        try:
            self.municipios = json.dumps(municipios_list)
        except TypeError as e:
            print(f"Error encoding list to JSON for vendedor ID {self.id}: {e}. Data: {municipios_list}")
            # Handle the error appropriately, maybe raise it or set to empty string
