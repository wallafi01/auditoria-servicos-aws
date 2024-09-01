import boto3
import csv
import os

# Configurações
aws_region = os.getenv('AWS_REGION', 'us-east-1')
s3_bucket_name = "analisecontas98"

# Inicializar boto3
session = boto3.Session(region_name=aws_region)
ec2_client = session.client('ec2')
iam_client = session.client('iam')
ecs_client = session.client('ecs')
rds_client = session.client('rds')
eks_client = session.client('eks')
s3_client = session.client('s3')

def audit_ec2_instances():
    response = ec2_client.describe_instances()
    instances = []
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            volumes = ec2_client.describe_volumes(
                Filters=[{'Name': 'attachment.instance-id', 'Values': [instance['InstanceId']]}]
            )
            volume_types = [vol['VolumeType'] for vol in volumes['Volumes']]  # Correção aqui

            name = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), None)

            public_ip = instance.get('PublicIpAddress', 'N/A')
            private_ip = instance.get('PrivateIpAddress', 'N/A')

            instance_info = {
                'InstanceId': instance['InstanceId'],
                'InstanceName': name,
                'InstanceType': instance['InstanceType'],
                'State': instance['State']['Name'],
                'LaunchTime': instance['LaunchTime'].strftime("%Y-%m-%d %H:%M:%S"),
                'VolumeTypes': ', '.join(volume_types),
                'PublicIpAddress': public_ip,
                'PrivateIpAddress': private_ip
            }
            instances.append(instance_info)
    return instances

def audit_iam_users():
    response = iam_client.list_users()
    users = []
    for user in response['Users']:
        user_info = {
            'UserName': user['UserName'],
            'UserId': user['UserId'],
            'Arn': user['Arn'],
            'CreateDate': user['CreateDate'].strftime("%Y-%m-%d %H:%M:%S"),
            'PasswordLastUsed': user.get('PasswordLastUsed', 'Never').strftime("%Y-%m-%d %H:%M:%S") if user.get('PasswordLastUsed') else 'Never'
        }
        users.append(user_info)
    return users

def audit_ecs_clusters():
    response = ecs_client.list_clusters()
    clusters = []
    for cluster_arn in response['clusterArns']:
        cluster_info = ecs_client.describe_clusters(clusters=[cluster_arn])
        for cluster in cluster_info['clusters']:
            clusters.append({
                'ClusterName': cluster['clusterName'],
                'Status': cluster['status'],
                'RunningTasksCount': cluster['runningTasksCount'],
                'PendingTasksCount': cluster['pendingTasksCount'],
                'ActiveServicesCount': cluster['activeServicesCount'],
                'RegisteredContainerInstancesCount': cluster['registeredContainerInstancesCount']
            })
    return clusters

def audit_rds_instances():
    response = rds_client.describe_db_instances()
    instances = []
    for db_instance in response['DBInstances']:
        instances.append({
            'DBInstanceIdentifier': db_instance['DBInstanceIdentifier'],
            'DBInstanceClass': db_instance['DBInstanceClass'],
            'Engine': db_instance['Engine'],
            'DBInstanceStatus': db_instance['DBInstanceStatus'],
            'MasterUsername': db_instance['MasterUsername'],
            'Endpoint': db_instance['Endpoint']['Address'],
            'AllocatedStorage': db_instance['AllocatedStorage'],
            'InstanceCreateTime': db_instance['InstanceCreateTime'].strftime("%Y-%m-%d %H:%M:%S")
        })
    return instances

def audit_eks_clusters():
    response = eks_client.list_clusters()
    clusters = []
    for cluster_name in response['clusters']:
        cluster_info = eks_client.describe_cluster(name=cluster_name)
        cluster = cluster_info['cluster']
        clusters.append({
            'ClusterName': cluster['name'],
            'Status': cluster['status'],
            'RoleArn': cluster['roleArn'],
            'Version': cluster['version'],
            'Endpoint': cluster['endpoint'],
            'CreatedAt': cluster['createdAt'].strftime("%Y-%m-%d %H:%M:%S")
        })
    return clusters

def generate_csv_report(data, file_name):
    if not data:
        print(f"Nenhum dado encontrado para {file_name}. Pulando a geração do relatório.")
        return

    keys = data[0].keys()
    with open(file_name, 'w', newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, fieldnames=keys)
        dict_writer.writeheader()
        dict_writer.writerows(data)

def upload_to_s3(file_name, bucket_name):
    if os.path.exists(file_name):
        s3_client.upload_file(file_name, bucket_name, file_name)
        os.remove(file_name)
    else:
        print(f"Arquivo {file_name} não encontrado. Não foi possível fazer o upload.")

if __name__ == "__main__":
    # Auditando as instâncias EC2
    instances_data = audit_ec2_instances()
    ec2_report_file_name = "ec2_audit_report.csv"
    generate_csv_report(instances_data, ec2_report_file_name)
    upload_to_s3(ec2_report_file_name, s3_bucket_name)
    
    # Auditando os usuários IAM
    iam_users_data = audit_iam_users()
    iam_report_file_name = "iam_users_audit_report.csv"
    generate_csv_report(iam_users_data, iam_report_file_name)
    upload_to_s3(iam_report_file_name, s3_bucket_name)

    # Auditando os clusters ECS
    ecs_clusters_data = audit_ecs_clusters()
    ecs_report_file_name = "ecs_clusters_audit_report.csv"
    generate_csv_report(ecs_clusters_data, ecs_report_file_name)
    upload_to_s3(ecs_report_file_name, s3_bucket_name)

    # Auditando as instâncias RDS
    rds_instances_data = audit_rds_instances()
    rds_report_file_name = "rds_instances_audit_report.csv"
    generate_csv_report(rds_instances_data, rds_report_file_name)
    upload_to_s3(rds_report_file_name, s3_bucket_name)

    # Auditando os clusters EKS
    eks_clusters_data = audit_eks_clusters()
    eks_report_file_name = "eks_clusters_audit_report.csv"
    generate_csv_report(eks_clusters_data, eks_report_file_name)
    upload_to_s3(eks_report_file_name, s3_bucket_name)

    print(f"Relatórios gerados e enviados para o S3: {s3_bucket_name}")
