module ChaCha20
  class Cipher
    def initialize(key, nonce, cipher: :salsa20_core)
      @cipher = case cipher
                when :salsa20_spec
                  Salsa20Specification.new(key, nonce)
                when :salsa20_core
                  Salsa20Core.new(key, nonce)
                else
                  raise ArgumentError, "unknown cipher: #{cipher}"
                end
      @position = 0
    end

    def seek(position)
      raise ArgumentError, "position must be a non-negative integer" unless position.is_a?(Integer) && position >= 0
      @position = position
    end

    def keystream(length)
      raise ArgumentError, "length must be a non-negative integer" unless length.is_a?(Integer) && length >= 0
      buffer = IO::Buffer.new(length)
      while length > 0
        block = @cipher.keystream_block(@position / @cipher.block_size)
        unconsumed_block_bytes = [length, @cipher.block_size - (@position % @cipher.block_size)].min
        buffer.copy(block, buffer.size - length, unconsumed_block_bytes, @position % @cipher.block_size)
        length -= unconsumed_block_bytes
        @position += unconsumed_block_bytes
      end
      buffer
    end

    def encrypt(plaintext)
      raise ArgumentError, "plaintext must be a string" unless plaintext.is_a?(String)
      result = IO::Buffer.for(plaintext).dup
      result.xor!(keystream(plaintext.bytesize)).get_string
    end

    alias_method :decrypt, :encrypt
  end
end
