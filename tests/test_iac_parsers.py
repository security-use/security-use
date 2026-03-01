"""Tests for IaC parsers."""

import pytest

from security_use.iac.terraform import TerraformParser
from security_use.iac.cloudformation import CloudFormationParser


class TestTerraformParser:
    """Tests for Terraform HCL2 parser."""

    def test_parse_simple_resource(self):
        content = '''
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  acl    = "private"
}
'''
        parser = TerraformParser()
        result = parser.parse(content, "main.tf")

        assert len(result.resources) == 1
        assert result.resources[0].resource_type == "aws_s3_bucket"
        assert result.resources[0].name == "example"
        assert result.resources[0].config["bucket"] == "my-bucket"
        assert result.resources[0].provider == "aws"

    def test_parse_multiple_resources(self):
        content = '''
resource "aws_s3_bucket" "bucket1" {
  bucket = "bucket-1"
}

resource "aws_s3_bucket" "bucket2" {
  bucket = "bucket-2"
}
'''
        parser = TerraformParser()
        result = parser.parse(content, "main.tf")

        assert len(result.resources) == 2

    def test_parse_data_source(self):
        content = '''
data "aws_caller_identity" "current" {}
'''
        parser = TerraformParser()
        result = parser.parse(content, "main.tf")

        assert len(result.resources) == 1
        assert result.resources[0].resource_type == "data.aws_caller_identity"
        assert result.resources[0].name == "current"

    def test_parse_variables(self):
        content = '''
variable "region" {
  default = "us-east-1"
}

variable "environment" {
  type = string
}
'''
        parser = TerraformParser()
        result = parser.parse(content, "variables.tf")

        assert "region" in result.variables
        assert "environment" in result.variables
        assert result.variables["region"]["default"] == "us-east-1"

    def test_parse_outputs(self):
        content = '''
output "bucket_arn" {
  value = aws_s3_bucket.example.arn
}
'''
        parser = TerraformParser()
        result = parser.parse(content, "outputs.tf")

        assert "bucket_arn" in result.outputs

    def test_parse_invalid_hcl(self):
        content = "this is not valid HCL {"
        parser = TerraformParser()
        result = parser.parse(content, "invalid.tf")

        assert len(result.errors) > 0

    def test_provider_detection(self):
        parser = TerraformParser()

        assert parser._get_provider("aws_s3_bucket") == "aws"
        assert parser._get_provider("azurerm_resource_group") == "azure"
        assert parser._get_provider("google_compute_instance") == "gcp"
        assert parser._get_provider("kubernetes_deployment") == "kubernetes"
        assert parser._get_provider("unknown_resource") == "unknown"

    def test_find_resource_line(self):
        content = '''# Comment
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
}
'''
        parser = TerraformParser()
        line = parser._find_resource_line(content, "aws_s3_bucket", "example")
        assert line == 2


class TestCloudFormationParser:
    """Tests for CloudFormation parser."""

    def test_parse_yaml_template(self):
        content = '''
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-bucket
'''
        parser = CloudFormationParser()
        result = parser.parse(content, "template.yaml")

        assert len(result.resources) == 1
        assert result.resources[0].resource_type == "AWS::S3::Bucket"
        assert result.resources[0].name == "MyBucket"
        assert result.resources[0].config["BucketName"] == "my-bucket"
        assert result.resources[0].provider == "aws"

    def test_parse_json_template(self):
        content = '''
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "MyBucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": {
        "BucketName": "my-bucket"
      }
    }
  }
}
'''
        parser = CloudFormationParser()
        result = parser.parse(content, "template.json")

        assert len(result.resources) == 1
        assert result.resources[0].name == "MyBucket"

    def test_parse_parameters(self):
        content = '''
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  Environment:
    Type: String
    Default: dev
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
'''
        parser = CloudFormationParser()
        result = parser.parse(content, "template.yaml")

        assert "Environment" in result.variables
        assert result.variables["Environment"]["Default"] == "dev"

    def test_parse_outputs(self):
        content = '''
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
Outputs:
  BucketArn:
    Value: !GetAtt MyBucket.Arn
'''
        parser = CloudFormationParser()
        result = parser.parse(content, "template.yaml")

        assert "BucketArn" in result.outputs

    def test_parse_invalid_yaml(self):
        content = "this: is: not: valid: yaml:"
        parser = CloudFormationParser()
        result = parser.parse(content, "invalid.yaml")

        # Should have an error about not being a valid template
        assert len(result.resources) == 0

    def test_non_cloudformation_yaml(self):
        content = '''
name: my-config
version: 1.0
'''
        parser = CloudFormationParser()
        result = parser.parse(content, "config.yaml")

        assert len(result.errors) > 0
        assert "not a valid CloudFormation template" in result.errors[0]

    def test_find_resource_line_yaml(self):
        content = '''AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
'''
        parser = CloudFormationParser()
        line = parser._find_resource_line(content, "MyBucket")
        assert line == 3


class TestIaCResource:
    """Tests for IaCResource helper methods."""

    def test_get_config_simple(self):
        from security_use.iac.base import IaCResource

        resource = IaCResource(
            resource_type="aws_s3_bucket",
            name="test",
            config={"bucket": "my-bucket", "acl": "private"},
            file_path="main.tf",
            line_number=1,
        )

        assert resource.get_config("bucket") == "my-bucket"
        assert resource.get_config("acl") == "private"
        assert resource.get_config("missing") is None
        assert resource.get_config("missing", default="default") == "default"

    def test_get_config_nested(self):
        from security_use.iac.base import IaCResource

        resource = IaCResource(
            resource_type="aws_s3_bucket",
            name="test",
            config={
                "server_side_encryption_configuration": {
                    "rule": {
                        "apply_server_side_encryption_by_default": {
                            "sse_algorithm": "aws:kms"
                        }
                    }
                }
            },
            file_path="main.tf",
            line_number=1,
        )

        result = resource.get_config(
            "server_side_encryption_configuration",
            "rule",
            "apply_server_side_encryption_by_default",
            "sse_algorithm",
        )
        assert result == "aws:kms"
