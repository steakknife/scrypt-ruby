if RUBY_ENGINE == 'jruby'
  autoload :Benchmark, 'benchmark'
  autoload :Digest, 'digest'
  autoload :OpenSSL, 'openssl'
  require File.expand_path('../scrypt-1.4.0.jar', __FILE__)
  module SCrypt
    @@debug = false
    def self.debug=(d)
      @@debug = d
    end

    def self.debug(*args)
      return @@debug if args.length == 0
      $stderr.puts(*args) if @@debug
    end

    module Errors
      class InvalidHash < StandardError; end
      class InvalidSalt < StandardError; end
      class InvalidSecret < StandardError; end
    end

    class Password < String
      attr_reader :cost, :digest, :salt

      def initialize(encrypted_password)
        encrypted_password = encrypted_password.to_s
        raise Errors::InvalidHash, "invalid hash" unless valid_hash? encrypted_password
        @cost, @salt, @digest = split_hash(replace(encrypted_password))
      end

      def self.create(plaintext_password, options = {})
        options = Engine::DEFAULTS.merge(options)
        key_len = [[options.delete(:key_len), 16].max, 512].min
        options[:salt_size] = [[options[:salt_size], 8].max, 32].min
        salt = Engine.generate_salt(options)
        hash = Engine.hash_secret(plaintext_password, salt, key_len)
        new(hash)
      end

      def ==(plaintext_password)
        self.class.secure_compare(self, Engine.hash_secret(plaintext_password, @cost + @salt, self.digest.length / 2))
      end

      alias :is_password? :==

    private
      def self.secure_compare(x, y)
       x.bytesize == y.bytesize && x.bytes.zip(y.bytes).inject(0) { |res, b| res |= b.inject(:^) } == 0
      end

      def split_hash(h)
        n, v, r, salt, hash = h.to_s.split('$')
       [[n, v, r].join('$') + "$", salt, hash]
      end

      def valid_hash?(h)
        !!h.match(/^[0-9a-z]+\$[0-9a-z]+\$[0-9a-z]+\$[A-Za-z0-9]{16,64}\$[A-Za-z0-9]{32,1024}$/)
      end 
    end # Password

    class Engine
      DEFAULTS = {
        key_len: 32,
        salt_size: 32,
        max_mem: 16 * 1024 * 1024, # 16 MiB
        max_memfrac: 0.5,
        max_time: 0.2,
        cost: nil
      }
      
      # @param plaintext_password String
      # @param salt String
      # @param args [String, key_len] or [n, r, p, key_len]
      def self.scrypt(plaintext_password, salt, *args)
        key_len = args.last
        n = r = p = nil
        case args.length
        when 2
          n, r, p = args[0].split('$').map{ |x| x.to_i(16) }
        when 4
          n, r, p = args
        else
          raise ArgumentError, 'only 4 or 6 arguments allowed'
        end
        raw_encrypted_password = com.lambdaworks.crypto.SCrypt.scrypt(plaintext_password.to_s.to_java_bytes, salt.to_java_bytes, n, r, p, key_len)
        String.from_java_bytes raw_encrypted_password
      end

      # "4000$8$4$c6d101522d3cb045"
      def self.generate_salt(options = {})
        options = DEFAULTS.merge(options)
        cost = options[:cost] || calibrate(options)
        salt_size = options.delete :salt_size
        salt = OpenSSL::Random.random_bytes(salt_size).unpack('H*').first.rjust(16,'0')
        if salt.length == 40
          #If salt is 40 characters, the regexp will think that it is an old-style hash, so add a '0'.
          salt = '0' + salt
        end
        cost + salt
      end

      #   N   r p
      # "4000$8$4$"
      def self.calibrate!(options = {})
        DEFAULTS[:cost] = calibrate(options)
      end

      def self.debug(*args)
        SCrypt.debug(*args)
      end

      #   N  r p
      # "400$8$25$"
      def self.calibrate(options = {})
        options = DEFAULTS.merge(options)
        max_mem = options.delete :max_mem
        max_memfrac = options.delete :max_memfrac
        max_time = options.delete :max_time

        mem_limit = memtouse(max_mem, max_memfrac)
        ops_limit = [cpuperf * max_time, 32768].min
        debug "ops_limit #{ops_limit} ops"

        n, r, p = nil, 8, nil

        if ops_limit < mem_limit/32
          debug "pick based on CPU limit"
          # Set p = 1 and choose N based on the CPU limit. 
          p = 1
          max_n = ops_limit / (r * 4)
          n = 1 << (1...63).find { |i| (1 << i) > max_n / 2 }
	      else
          debug "pick based on memory limit"
          # Set N based on the memory limit. */
      		max_n = mem_limit / (r * 128)
          n = 1 << (1..63).find { |i| (1 << i) > max_n / 2 }

          # Choose p based on the CPU limit. */
          max_rp = [(ops_limit / 4) / (1 << n), 0x3fffffff].min
          p = max_rp / r
        end
        debug "calibrated using: N #{n} r #{r} p #{p}"
        "#{n.to_s(16)}$#{r.to_s(16)}$#{p.to_s(16)}$"
      end

      # @returns Boolean
      def self.valid_cost?(cost)
        !!cost.match(/^[0-9a-z]+\$[0-9a-z]+\$[0-9a-z]+\$$/)
      end

      # @returns Boolean
      def self.valid_salt?(salt)
        !!salt.match(/^[0-9a-z]+\$[0-9a-z]+\$[0-9a-z]+\$[A-Za-z0-9]{16,64}$/)
      end

      # @returns Boolean
      def self.valid_secret?(secret)
        secret.respond_to?(:to_s)
      end

      def self.hash_secret_old(secret, salt, cost)
        salt + "$" + Digest::SHA1.hexdigest(scrypt(secret.to_s, salt, cost, 256))
      end

      def self.hash_secret_new(secret, salt_only, cost, key_len)
        salt_only = [salt_only.sub(/^(00)+/, '')].pack('H*')
        scrypt(secret.to_s, salt_only, cost, key_len).unpack('H*').first.rjust(key_len * 2, '0')
      end

      # "400$8$26$b62e0f787a5fc373$0399ccd4fa26642d92741b17c366b7f6bd12ccea5214987af445d2bed97bc6a2"
      def self.hash_secret(secret, salt, key_len = DEFAULTS[:key_len])
        raise Errors::InvalidSalt, "invalid salt" unless valid_salt? salt
        raise Errors::InvalidSecret, "invalid secret" unless valid_secret? secret

         cost = cost_from_salt(salt)
         salt_only = salt_only(salt)

         if salt_only.length == 40
           hash_secret_old(secret, salt, cost)
         else
           salt + "$" + hash_secret_new(secret, salt_only, cost, key_len)
         end
      end

      private

      def self.cost_from_salt(salt)
        salt[/^[0-9a-z]+\$[0-9a-z]+\$[0-9a-z]+\$/]
      end

      def self.salt_only(salt)
        salt[/\$([A-Za-z0-9]{16,64})$/, 1]
      end

      # Estimate how many scrypts / second
      def self.cpuperf
        iterations = 1000
        empty_array = "".to_java_bytes.freeze
        run = -> { iterations.times { com.lambdaworks.crypto.SCrypt.scrypt(empty_array, empty_array, 128, 1, 1, 1) } }
        # warm-up
        run.()
        loop do 
          time = Benchmark.realtime { |x| run.() }
          if time > 0.33
            per_sec = iterations/time
            debug "cpuperf #{per_sec} ops/s"
            return per_sec
          end
          iterations *= 10
        end
      end

      # 
      def self.memtouse(max_mem, max_memfrac)
        max_memfrac = 0.5 if max_memfrac > 0.5 || max_memfrac == 0

        memlimit_min = java.lang.Runtime.getRuntime.freeMemory
        debug "free mem #{memlimit_min / 1048576} MiB"

      	mem_avail = max_memfrac * memlimit_min
        mem_avail = [mem_avail, max_mem].min if max_mem > 0
        mem_avail = [mem_avail, 1024*1024].max
        debug "memtouse #{mem_avail / 1048576} MiB"
        mem_avail
      end
    end # Engine
  end # SCrypt
else
  require 'scrypt'
end
