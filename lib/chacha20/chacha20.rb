module ChaCha20
  class ChaCha20
    def initialize(key, nonce)
      raise ArgumentError, "key must be 32 bytes" unless key.bytesize == 32
      raise ArgumentError, "nonce must be 8 bytes" unless nonce.bytesize == 8
      @matrix = prepare_matrix(key, nonce)
    end

    def block_size = 64

    def keystream_block(c)
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

      @matrix[12], @matrix[13] = c_bytes.unpack("L<2")
      chacha20_hash(@matrix)
    end

    private

    def prepare_matrix(key, nonce)
      sigma = "expand 32-byte k".unpack("L<4")
      k = key.unpack("L<8")
      n = nonce.unpack("L<2")
      [
        sigma[0], sigma[1], sigma[2], sigma[3],
        k[0], k[1], k[2], k[3],
        k[4], k[5], k[6], k[7],
        # two 0s as placeholder for counter
        0, 0, n[0], n[1]
      ]
    end

    def leftrotate32(u, c)
      ((u << c) & 0xffffffff) | (u >> (32 - c))
    end

    def chacha20_hash(xs)
      z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10, z11, z12, z13, z14, z15 = xs

      10.times do
        z0 = (z0 + z4) & 0xffffffff; z12 ^= z0; z12 = leftrotate32(z12, 16)
        z8 = (z8 + z12) & 0xffffffff; z4 ^= z8; z4 = leftrotate32(z4, 12)
        z0 = (z0 + z4) & 0xffffffff; z12 ^= z0; z12 = leftrotate32(z12, 8)
        z8 = (z8 + z12) & 0xffffffff; z4 ^= z8; z4 = leftrotate32(z4, 7)

        z1 = (z1 + z5) & 0xffffffff; z13 ^= z1; z13 = leftrotate32(z13, 16)
        z9 = (z9 + z13) & 0xffffffff; z5 ^= z9; z5 = leftrotate32(z5, 12)
        z1 = (z1 + z5) & 0xffffffff; z13 ^= z1; z13 = leftrotate32(z13, 8)
        z9 = (z9 + z13) & 0xffffffff; z5 ^= z9; z5 = leftrotate32(z5, 7)

        z2 = (z2 + z6) & 0xffffffff; z14 ^= z2; z14 = leftrotate32(z14, 16)
        z10 = (z10 + z14) & 0xffffffff; z6 ^= z10; z6 = leftrotate32(z6, 12)
        z2 = (z2 + z6) & 0xffffffff; z14 ^= z2; z14 = leftrotate32(z14, 8)
        z10 = (z10 + z14) & 0xffffffff; z6 ^= z10; z6 = leftrotate32(z6, 7)

        z3 = (z3 + z7) & 0xffffffff; z15 ^= z3; z15 = leftrotate32(z15, 16)
        z11 = (z11 + z15) & 0xffffffff; z7 ^= z11; z7 = leftrotate32(z7, 12)
        z3 = (z3 + z7) & 0xffffffff; z15 ^= z3; z15 = leftrotate32(z15, 8)
        z11 = (z11 + z15) & 0xffffffff; z7 ^= z11; z7 = leftrotate32(z7, 7)

        z0 = (z0 + z5) & 0xffffffff; z15 ^= z0; z15 = leftrotate32(z15, 16)
        z10 = (z10 + z15) & 0xffffffff; z5 ^= z10; z5 = leftrotate32(z5, 12)
        z0 = (z0 + z5) & 0xffffffff; z15 ^= z0; z15 = leftrotate32(z15, 8)
        z10 = (z10 + z15) & 0xffffffff; z5 ^= z10; z5 = leftrotate32(z5, 7)

        z1 = (z1 + z6) & 0xffffffff; z12 ^= z1; z12 = leftrotate32(z12, 16)
        z11 = (z11 + z12) & 0xffffffff; z6 ^= z11; z6 = leftrotate32(z6, 12)
        z1 = (z1 + z6) & 0xffffffff; z12 ^= z1; z12 = leftrotate32(z12, 8)
        z11 = (z11 + z12) & 0xffffffff; z6 ^= z11; z6 = leftrotate32(z6, 7)

        z2 = (z2 + z7) & 0xffffffff; z13 ^= z2; z13 = leftrotate32(z13, 16)
        z8 = (z8 + z13) & 0xffffffff; z7 ^= z8; z7 = leftrotate32(z7, 12)
        z2 = (z2 + z7) & 0xffffffff; z13 ^= z2; z13 = leftrotate32(z13, 8)
        z8 = (z8 + z13) & 0xffffffff; z7 ^= z8; z7 = leftrotate32(z7, 7)

        z3 = (z3 + z4) & 0xffffffff; z14 ^= z3; z14 = leftrotate32(z14, 16)
        z9 = (z9 + z14) & 0xffffffff; z4 ^= z9; z4 = leftrotate32(z4, 12)
        z3 = (z3 + z4) & 0xffffffff; z14 ^= z3; z14 = leftrotate32(z14, 8)
        z9 = (z9 + z14) & 0xffffffff; z4 ^= z9; z4 = leftrotate32(z4, 7)
      end

      result = IO::Buffer.new(64)
      result.set_values(
        [:u32, :u32, :u32, :u32, :u32, :u32, :u32, :u32, :u32, :u32, :u32, :u32, :u32, :u32, :u32, :u32],
        0,
        [
          (z0 + xs[0]) & 0xffffffff,
          (z1 + xs[1]) & 0xffffffff,
          (z2 + xs[2]) & 0xffffffff,
          (z3 + xs[3]) & 0xffffffff,
          (z4 + xs[4]) & 0xffffffff,
          (z5 + xs[5]) & 0xffffffff,
          (z6 + xs[6]) & 0xffffffff,
          (z7 + xs[7]) & 0xffffffff,
          (z8 + xs[8]) & 0xffffffff,
          (z9 + xs[9]) & 0xffffffff,
          (z10 + xs[10]) & 0xffffffff,
          (z11 + xs[11]) & 0xffffffff,
          (z12 + xs[12]) & 0xffffffff,
          (z13 + xs[13]) & 0xffffffff,
          (z14 + xs[14]) & 0xffffffff,
          (z15 + xs[15]) & 0xffffffff
        ]
      )
      result
    end
  end
end
