require "doorkeeper-jwt/version"
require "doorkeeper-jwt/config"
require 'jwt'

module Doorkeeper
  module JWT
    class << self
      def validate(token, opts = {})
        ::JWT.decode(
          token,
          public_key,
          encryption_method
        )
      end

      def generate(opts = {})
        ::JWT.encode(
          token_payload(opts),
          secret_key,
          encryption_method,
          header_payload(opts)
        )
      end

      private

      def token_payload(opts = {})
        Doorkeeper::JWT.configuration.token_payload.call opts
      end

      def header_payload(opts = {})
        Doorkeeper::JWT.configuration.header_payload.call opts
      end

      def public_key
        return public_key_method unless public_key_method.nil?
        return public_key_file unless public_key_file.nil?
        return public_rsa_key if rsa_encryption?
        return public_ecdsa_key if ecdsa_encryption?
        Doorkeeper::JWT.configuration.secret_key
      end

      def secret_key
        return secret_key_method unless secret_key_method.nil?
        return secret_key_file unless secret_key_file.nil?
        return secret_rsa_key if rsa_encryption?
        return secret_ecdsa_key if ecdsa_encryption?
        Doorkeeper::JWT.configuration.secret_key
      end

      def public_key_method
        method = Doorkeeper::JWT.configuration.public_key_method.call
        method.nil? ? nil : method
      end

      def public_key_file
        return nil if Doorkeeper::JWT.configuration.public_key_path.nil?
        return public_rsa_key_file if rsa_encryption?
        return public_ecdsa_key_file if ecdsa_encryption?
      end

      def secret_key_method
        method = Doorkeeper::JWT.configuration.secret_key_method.call
        method.nil? ? nil : method
      end

      def secret_key_file
        return nil if Doorkeeper::JWT.configuration.secret_key_path.nil?
        return secret_rsa_key_file if rsa_encryption?
        return secret_ecdsa_key_file if ecdsa_encryption?
      end

      def encryption_method
        return nil unless Doorkeeper::JWT.configuration.encryption_method
        Doorkeeper::JWT.configuration.encryption_method.to_s.upcase
      end

      def rsa_encryption?
        /RS\d{3}/ =~ encryption_method
      end

      def ecdsa_encryption?
        /ES\d{3}/ =~ encryption_method
      end

      def public_rsa_key
        OpenSSL::PKey::RSA.new(Doorkeeper::JWT.configuration.public_key)
      end

      def public_ecdsa_key
        OpenSSL::PKey::EC.new(Doorkeeper::JWT.configuration.public_key)
      end

      def secret_rsa_key
        OpenSSL::PKey::RSA.new(Doorkeeper::JWT.configuration.secret_key)
      end

      def secret_ecdsa_key
        OpenSSL::PKey::EC.new(Doorkeeper::JWT.configuration.secret_key)
      end

      def secret_rsa_key_file
        OpenSSL::PKey::RSA.new(secret_key_file_open)
      end

      def secret_ecdsa_key_file
        OpenSSL::PKey::EC.new(secret_key_file_open)
      end

      def public_rsa_key_file
        OpenSSL::PKey::RSA.new(public_key_file_open)
      end

      def public_ecdsa_key_file
        OpenSSL::PKey::EC.new(public_key_file_open)
      end

      def secret_key_file_open
        File.open(Doorkeeper::JWT.configuration.secret_key_path)
      end

      def public_key_file_open
        File.open(Doorkeeper::JWT.configuration.public_key_path)
      end
    end
  end
end
