require 'fluent/filter'
require 'openssl'
require 'base64'

module Fluent
  class EncryptFilter < Filter
    Fluent::Plugin.register_filter('encrypt', self)

    SUPPORTED_ALGORITHMS = {
        aes_256_cbc: { name: "AES-256-CBC", use_iv: true },
        aes_192_cbc: { name: "AES-192-CBC", use_iv: true },
        aes_128_cbc: { name: "AES-128-CBC", use_iv: true },
        aes_256_ecb: { name: "AES-256-ECB", use_iv: false },
        aes_192_ecb: { name: "AES-192-ECB", use_iv: false },
        aes_128_ecb: { name: "AES-128-ECB", use_iv: false },
    }

    config_param :algorithm, :enum, list: SUPPORTED_ALGORITHMS.keys, default: :aes_128_cbc
    config_param :encrypt_key_hex, :string
    config_param :encrypt_iv_hex, :string, default: nil

    config_param :encrypt_enable, :string, default: :y

    config_param :key,  :string, default: nil
    config_param :keys, :array, default: []

    attr_reader :target_keys

    def configure(conf)
      super

      @target_keys = @keys + [@key]
      #if @target_keys.empty?
      #   raise Fluent::ConfigError, "no keys specified to be encrypted"
      #end

      algorithm = SUPPORTED_ALGORITHMS[@algorithm]
      if algorithm[:use_iv] && !@encrypt_iv_hex
        raise Fluent::ConfigError, "Encryption algorithm #{@algorithm} requires 'encrypt_iv_hex'"
      end

      puts "encrypt_key_hex=#{@encrypt_key_hex}"
      @enc_key = Base64.decode64(@encrypt_key_hex)
      puts "enc_key=#{@enc_key}"

      puts "encrypt_iv_hex=#{@encrypt_iv_hex}"
      @enc_iv = if @encrypt_iv_hex
                  Base64.decode64(@encrypt_iv_hex)
                else
                  nil
                end
      puts "enc_iv=#{@enc_iv}"

      puts "encrypt_enable=#{@encrypt_enable}"
      @enc_enable = @encrypt_enable
      puts "enc_enable=#{@enc_enable}"

      @enc_generator = ->(){
        enc = OpenSSL::Cipher.new(algorithm[:name])
        enc.encrypt
        enc.key = @enc_key
        enc.iv  = @enc_iv if @enc_iv
        enc
      }
    end

    def filter_stream(tag, es)
      new_es = MultiEventStream.new
      es.each do |time, record|
        r = record.dup
        if @encrypt_enable == "y"
          if target_keys.at(0) == nil
            # encrypt all the payload
            e = encrypt(r.to_json).delete!("\n")
            payload = {"encrypt" => e}
            new_es.add(time, payload)
          else
            # encrypt the node to which the key points in the payload
            record.each_pair do |key, value|
              if @target_keys.include?(key)
                # puts "key=#{key}"
                # puts "key加密前的值1=#{value.to_json.strip}"
                # puts "key加密前的值1=#{value.to_json}"
                r[key] = encrypt(value.to_json).delete!("\n")
                # r[key] = r[key].delete!("\n")
                # puts "key加密后的值2=#{r[key]}"
              end
            end
            new_es.add(time, r)
          end
        else
          new_es.add(time, r)
        end
      end
      new_es
    end

    def encrypt(value)
      encrypted = ""
      enc = @enc_generator.call()
      encrypted << enc.update(value)
      encrypted << enc.final
      Base64.encode64(encrypted)
    end
  end
end