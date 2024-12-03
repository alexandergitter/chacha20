module ChaCha20
  class Salsa20Specification
    def initialize(key, nonce)
      raise ArgumentError, "key must be 32 bytes" unless key.bytesize == 32
      raise ArgumentError, "nonce must be 8 bytes" unless nonce.bytesize == 8
      @key = key
      @nonce = nonce
    end

    def block_size = 64

    def keystream_block(c)
      salsa20_keystream_block(@key, @nonce, c)
    end

    private

    def leftrotate32(u, c)
      ((u << c) & 0xffffffff) | (u >> (32 - c))
    end

    def quarterround(y0, y1, y2, y3)
      z1 = y1 ^ leftrotate32((y0 + y3) & 0xffffffff, 7)
      z2 = y2 ^ leftrotate32((z1 + y0) & 0xffffffff, 9)
      z3 = y3 ^ leftrotate32((z2 + z1) & 0xffffffff, 13)
      z0 = y0 ^ leftrotate32((z3 + z2) & 0xffffffff, 18)
      [z0, z1, z2, z3]
    end

    def rowround(y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, y10, y11, y12, y13, y14, y15)
      z0, z1, z2, z3 = quarterround(y0, y1, y2, y3)
      z5, z6, z7, z4 = quarterround(y5, y6, y7, y4)
      z10, z11, z8, z9 = quarterround(y10, y11, y8, y9)
      z15, z12, z13, z14 = quarterround(y15, y12, y13, y14)
      [z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10, z11, z12, z13, z14, z15]
    end

    def columnround(y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, y10, y11, y12, y13, y14, y15)
      z0, z4, z8, z12 = quarterround(y0, y4, y8, y12)
      z5, z9, z13, z1 = quarterround(y5, y9, y13, y1)
      z10, z14, z2, z6 = quarterround(y10, y14, y2, y6)
      z15, z3, z7, z11 = quarterround(y15, y3, y7, y11)
      [z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10, z11, z12, z13, z14, z15]
    end

    def doubleround(y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, y10, y11, y12, y13, y14, y15)
      rowround(*columnround(y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, y10, y11, y12, y13, y14, y15))
    end

    def salsa20_hash(x)
      x0 = x.get_value(:u32, 0)
      x1 = x.get_value(:u32, 4)
      x2 = x.get_value(:u32, 8)
      x3 = x.get_value(:u32, 12)
      x4 = x.get_value(:u32, 16)
      x5 = x.get_value(:u32, 20)
      x6 = x.get_value(:u32, 24)
      x7 = x.get_value(:u32, 28)
      x8 = x.get_value(:u32, 32)
      x9 = x.get_value(:u32, 36)
      x10 = x.get_value(:u32, 40)
      x11 = x.get_value(:u32, 44)
      x12 = x.get_value(:u32, 48)
      x13 = x.get_value(:u32, 52)
      x14 = x.get_value(:u32, 56)
      x15 = x.get_value(:u32, 60)
      z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10, z11, z12, z13, z14, z15 = x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15
      10.times do
        z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10, z11, z12, z13, z14, z15 = doubleround(z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10, z11, z12, z13, z14, z15)
      end
      x.set_value(:u32, 0, (z0 + x0) & 0xffffffff)
      x.set_value(:u32, 4, (z1 + x1) & 0xffffffff)
      x.set_value(:u32, 8, (z2 + x2) & 0xffffffff)
      x.set_value(:u32, 12, (z3 + x3) & 0xffffffff)
      x.set_value(:u32, 16, (z4 + x4) & 0xffffffff)
      x.set_value(:u32, 20, (z5 + x5) & 0xffffffff)
      x.set_value(:u32, 24, (z6 + x6) & 0xffffffff)
      x.set_value(:u32, 28, (z7 + x7) & 0xffffffff)
      x.set_value(:u32, 32, (z8 + x8) & 0xffffffff)
      x.set_value(:u32, 36, (z9 + x9) & 0xffffffff)
      x.set_value(:u32, 40, (z10 + x10) & 0xffffffff)
      x.set_value(:u32, 44, (z11 + x11) & 0xffffffff)
      x.set_value(:u32, 48, (z12 + x12) & 0xffffffff)
      x.set_value(:u32, 52, (z13 + x13) & 0xffffffff)
      x.set_value(:u32, 56, (z14 + x14) & 0xffffffff)
      x.set_value(:u32, 60, (z15 + x15) & 0xffffffff)
      x
    end

    def salsa20_expand(k, n)
      sigma = "expand 32-byte k"
      x = IO::Buffer.new(64)
      x.set_string(sigma, 0, 4, 0)
      x.set_string(k, 4, 16, 0)
      x.set_string(sigma, 20, 4, 4)
      x.set_string(n, 24, 16, 0)
      x.set_string(sigma, 40, 4, 8)
      x.set_string(k, 44, 16, 16)
      x.set_string(sigma, 60, 4, 12)
      salsa20_hash(x)
    end

    def salsa20_keystream_block(k, n, c)
      raise ArgumentError, "key must be 32 bytes" unless k.bytesize == 32
      raise ArgumentError, "nonce must be 8 bytes" unless n.bytesize == 8
      c_bytes = case c
                when Integer
                  raise ArgumentError, "counter overflow - must not be more than 8 bytes" unless c.size <= 8
                  [c].pack("Q<")
                when String
                  raise ArgumentError, "counter must be 8 bytes" unless c.bytesize == 8
                  c
                else
                  raise ArgumentError, "counter must be an integer or a string"
                end

      salsa20_expand(k, n + c_bytes)
    end
  end
end
