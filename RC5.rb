class RC5
  W, R = 64, 12
  W4 = W/4
  W8 = W/8
  @b = 8
  T = 2 * (R + 1)
  MOD = 2 ** W
  MASK = MOD - 1
  P = 0xB7E151628AED2A6B
  Q = 0x9E3779B97F4A7C15


  def left_shift(val, n)
    n %= W
    ((val << n) & MASK) | ((val & MASK) >> (W - n))
  end

  def right_shift(val, n)
    n %= W
    ((val & MASK) >> n) | (val << (W - n) & MASK)
  end

  def initialize (key)
  	@key = key.bytes
    @b = @key.length    
    align_key
    @S = Array.new(T){|i| i = (P + i * Q) % MOD}
    shuffle
  end

  def align_key
    if @b == 0
      @c = 1
    elsif @b % W8 != 0
      @key += [0] * (W8 - @b % W8)
      @b = @key.length
      @c = @b / W8
    else
      @c = @b / W8
    end     
    @L = Array.new(@c) {|i| i = 0}
    i = @b - 1
    while i >= 0
      @L[i/W8] = (@L[i/W8]<<8) + @key[i]
      i-=1
    end   
  end

  def shuffle
  	i, j, a, b = 0, 0, 0, 0
  	for k in (0...(3 * [T, @c].max))
  		a = @S[i] = left_shift((@S[i] + a + b), 3)
  		b = @L[j] = left_shift((@L[j] + a + b), a + b)
  		i = (i + 1) % T
        j = (j + 1) % @c
  	end
  end

  def encrypt_block(data)  	
  	a = data[0...W8].pack("c*").unpack("Q")[0]
  	b = data[W8..-1].pack("c*").unpack("Q")[0]
  	a = (a + @S[0]) % MOD
    b = (b + @S[1]) % MOD
    for i in (1..R) do
    	a = (left_shift((a ^ b), b) + @S[2 * i]) % MOD
    	b = (left_shift((a ^ b), a) + @S[2 * i + 1]) % MOD    	
    end
    return [a].pack('Q').unpack('c*') + [b].pack('Q').unpack('c*')
  end

  def decrypt_block(data)
  	a = data[0...W8].pack("c*").unpack("Q")[0]
  	b = data[W8..-1].pack("c*").unpack("Q")[0]  	
  	i = R
  	while i > 0 do
  		b = right_shift(b - @S[2 * i + 1], a) ^ a
  		a = right_shift(a - @S[2 * i], b) ^ b
  		i -= 1
  	end
  	b = (b - @S[1]) % MOD
  	a = (a - @S[0]) % MOD  	
  	return [a].pack('Q').unpack('c*') + [b].pack('Q').unpack('c*')
  end

  def encrypt_text(text)
  	@plain, @data, run, res = text, text.bytes, true, []
  	while run
  		temp = @data[0...W4]
  		if temp.length != W4
  			(W4 - temp.length).times {temp << 0}
  			run = false
  		end
  		res += encrypt_block(temp)
  		@data = @data[W4..-1] 
  	end
  	return res.pack('c*')  	
  end

  def decrypt_text(data)  	
    data = data.unpack('c*')
  	res, run = [], true
  	while run do
  		temp = data[0...W4]
  		if temp.length != W4
  			run = false
  		end
  		res += decrypt_block(temp)
  		unless run
  			while res[-1] == 0
  				res.pop
  			end			
  		end
  		data = data[W4..-1]
  		break if  data.nil? || data.empty? 
  	end
  	return res.pack('c*')
  end

  def encrypt_file(ofile, sfile)
    run = true
    @save = File.open(sfile, 'w')
    File.open(ofile) do |file|
      until file.eof?
        block = file.read(W4).bytes
        break unless block
        if block.length != W4
          (W4 - block.length).times {block << 0}
          run = false
        end
        @save.write(encrypt_block(block).pack('c*'))
      end
    end
    @save.close
  end

  def decrypt_file(ofile, sfile)
    run = true
    @save = File.open(sfile, 'w+')
    File.open(ofile) do |file|
      until file.eof?
        block = file.read(W4).unpack('c*')
        break unless block
        if block.length != W4
          run = false
        end
        @save << decrypt_block(block).pack('c*')
      end
    end
    @save.close
  end
end
