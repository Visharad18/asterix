from pcapfile import savefile
import numpy as np
import pandas as pd
from sklearn.linear_model import LinearRegression
#import xgboost as xgb
from matplotlib import pyplot as plt

file=input('Enter pcap file name: ')
file=file+'.pcap'
def to_bits(a,i):
	a=int(a[i:i+2],16)
	b=bin(a%16)
	b=b[2:]
	while(len(b)!=4):
		b='0'+b
	c=bin(a//16)
	c=c[2:]
	while(len(c)!=4):
		c='0'+c
	return b+c

def process_pcap(file_name):
	print('Opening {}...'.format(file_name))
	count = 0
	testcap=open(file_name,'rb')
	capfile=savefile.load_savefile(testcap,verbose=True)
	
	csv=input('Enter File name for saving data & metadata: ')
	csv=csv+'.csv'
#	f=open(csv,'x')
#	f.write('PACKET NUMBER,')
#	f.write('HEADER,')
#	f.write('TIMESTAMP,')
#	f.write('TIMESTAMP US,')
#	f.write('CAPTURE LENGTH,')
#	f.write('PACKET LENGTH,')
#	f.write('PACKET\n')
	header=[]
	timestamp=[]
	timestamp_us=[]
	capture_len=[]
	packet_len=[]
	packet=[]
	bits=[]

	cat=[]
	length=[]
	fspec1=[]
	fspec2=[]
	fspec3=[]
	fspec4=[]
	
	fx1=[]
	fx2=[]
	fx3=[]
	fx4=[]
	
	sac=[]
	sic=[]
	time_of_day=[]
	target_report_descriptor_typ=[]
	target_report_descriptor_sim=[]
	target_report_descriptor_rdp=[]
	target_report_descriptor_spi=[]
	target_report_descriptor_rab=[]
	target_report_descriptor_fx=[]
	polar_coord_x=[]
	polar_coord_y=[]
	mode3acode=[]
	mode3acode_v=[]
	mode3acode_g=[]
	mode3acode_l=[]
	flight_level=[]
	flight_level_g=[]
	flight_level_v=[]
	radar_plot_char=[]

	aircraft_add=[]
	aircraft_id=[]
	modeSMBdata=[]
	track_num=[]
	cartesian_coord=[]
	track_velocity_polar=[]
	track_status=[]
	
	track_quality=[]
	warning=[]
	mode3aconfidence=[]
	modeCconfidence=[]
	height=[]
	radial_doppler_speed=[]
	
	acas_capability=[]
	mode1code=[]
	mode2code=[]
	mode1confidence=[]
	mode2confidence=[]
	special_purpose_field=[]
	reserved_expansion_field=[]

	df=pd.DataFrame()
	for pkt in capfile.packets:
		if pkt.packet_len>45:
			category=int(pkt.packet[84:86],16)
			#print(category)
			if category==48:
				count += 1
				header.append(pkt.header)
				timestamp.append(pkt.timestamp)
				timestamp_us.append(pkt.timestamp_us)
				capture_len.append(pkt.capture_len)
				packet_len.append(pkt.packet_len)
				packet.append(pkt.packet)
				#print(pkt.packet)
				cat.append(category)
				l=int(pkt.packet[86:90],16)
				length.append(l)
				f1=to_bits(pkt.packet,90)
				if f1[7]=='1':
					f2=to_bits(pkt.packet,92)
				else:
					f2=''
				if f2!='' and f2[7]=='1':
					f3=to_bits(pkt.packet,94)
				else:
					f3=''
				f=f1+f2+f3
				#print('f={}'.format(f))
				fspec1.append(f)
				x=96
				if f1[0]=='1':
					sac.append(int(pkt.packet[x:x+2],16))
					sic.append(int(pkt.packet[x+2:x+4],16))
					x=x+4
				else:
					sac.append('')
					sic.append('')
				if f1[1]=='1':
					time_of_day.append(int(pkt.packet[x:x+6],16)/128)
					x=x+6
				else:
					time_of_day.append('')
				if f1[2]=='1':
					trd1=to_bits(pkt.packet,x)
					#print(trd1)
					x=x+2
					typ=trd1[:3]
					if typ=='000':
						target_report_descriptor_typ.append('No Detection')
					elif typ=='001':
						target_report_descriptor_typ.append('Single PSR Detection')	
					elif typ=='010':
						target_report_descriptor_typ.append('Single SSR Detection')
					elif typ=='011':
						target_report_descriptor_typ.append('SSR + PSR Detection')
					elif typ=='100':
						target_report_descriptor_typ.append('Single ModeS All-Call')
					elif typ=='101':
						target_report_descriptor_typ.append('Single ModeS Roll-Call')
					elif typ=='110':
						target_report_descriptor_typ.append('ModeS All-Call + PSR')
					elif typ=='111':
						target_report_descriptor_typ.append('ModeS Roll-Call + PSR')
					else:
						target_report_descriptor_typ.append('')
					sim=trd1[3]
					if sim=='0':
						target_report_descriptor_sim.append('Actual target report')
					elif sim=='1':
						target_report_descriptor_sim.append('Simulated target report')
					else:
						target_report_descriptor_sim.append('')
					rdp=trd1[4]
					if rdp=='0':
						target_report_descriptor_rdp.append('Report from RDP chain 1')
					elif rdp=='1':
						target_report_descriptor_rdp.append('Report from RDP chain 2')
					else:
						target_report_descriptor_rdp.append('')
					spi=trd1[5]
					if spi=='0':
						target_report_descriptor_spi.append('Absence of SPI')
					elif spi=='1':
						target_report_descriptor_spi.append('Special Position Identification')
					else:
						target_report_descriptor_spi.append('')
					rab=trd1[6]
					if rab=='0':
						target_report_descriptor_rab.append('Report from aircraft transponder')
					elif rab=='1':
						target_report_descriptor_rab.append('Report from field monitor')
					else:
						target_report_descriptor_rab.append('')
					#print(trd1)
					if len(trd1)==8:
						trd_fx=trd1[7]
						while(trd_fx=='1'):
							trd1=to_bits(pkt.packet,x)
							#print(trd1)
							x=x+2
							trd1=trd1[2:]
							if len(trd1)==8:
								trd_fx=trd1[7]
							else:
								break
					else:
						continue
				else:
					target_report_descriptor_typ.append('')
					target_report_descriptor_sim.append('')
					target_report_descriptor_rdp.append('')
					target_report_descriptor_spi.append('')
					target_report_descriptor_rab.append('')
				if f1[3]=='1':
					polar_coord_x.append(int(pkt.packet[x:x+4],16)/128)
					polar_coord_y.append(int(pkt.packet[x+4:x+8],16)/128)
					x=x+8
				else:
					polar_coord_x.append('')
					polar_coord_y.append('')
				if f1[4]=='1':
					m3c=to_bits(pkt.packet,x)+to_bits(pkt.packet,x+2)
					if m3c[0]=='0':
						mode3acode_v.append('Code Validated')
					else:
						mode3acode_v.append('Code not Validated')
					if m3c[1]=='0':
						mode3acode_g.append('Default')
					else:
						mode3acode_g.append('Garbled code')
					if m3c[2]=='0':
						mode3acode_l.append('Mode-3/A code derived from the reply of the transponder ')
					else:
						mode3acode_l.append('Mode-3/A code not extracted during the last scan')
					mode3acode.append(int(m3c[4:],2))					
					x=x+4
				else:
					mode3acode_v.append('')
					mode3acode_g.append('')
					mode3acode_l.append('')
					mode3acode.append('')
				if f1[5]=='1':
					fl=to_bits(pkt.packet,x)+to_bits(pkt.packet,x+2)
					if fl[0]=='0':
						flight_level_v.append('Code Validated')
					else:
						flight_level_v.append('Code not Validated')
					if fl[1]=='1':
						flight_level_g.append('Default')
					else:
						flight_level_g.append('Garbled Code')
					flight_level.append(int(fl[2:],2)/14)
					x=x+4
				else:
					flight_level_g.append('')
					flight_level_v.append('')
					flight_level.append('')

			#print(category)
			#print(l)
			#print(f)

	df['HEADER']=header
	df['TIMESTAMP']=timestamp
	df['TIMESTAMP_US']=timestamp_us
	df['CAPTURE_LEN']=capture_len
	df['PACKET_LEN']=packet_len
	df['PACKET']=packet
	df['CATEGORY']=cat
	df['DATA_LENGTH']=length
	df['FSPEC1']=fspec1
	df['SYSTEM_AREA_CODE']=sac
	df['SYSTEM_IDENTIFICATION_CODE']=sic
	df['TIME_OF_DAY']=time_of_day
	df['TARGET_REPORT_DESCRIPTOR_TYP']=target_report_descriptor_typ
	df['TARGET_REPORT_DESCRIPTOR_SIM']=target_report_descriptor_sim
	df['TARGET_REPORT_DESCRIPTOR_RDP']=target_report_descriptor_rdp
	df['TARGET_REPORT_DESCRIPTOR_SPI']=target_report_descriptor_spi
	df['TARGET_REPORT_DESCRIPTOR_RAB']=target_report_descriptor_rab
	df['X_POLAR_COORDINATE']=polar_coord_x
	df['Y_POLAR_COORDINATE']=polar_coord_y
	df['MODE-3A_CODE']=mode3acode
	df['MODE-3A_CODE_VALIDATION']=mode3acode_v
	df['MODE-3A_CODE_GARBLE']=mode3acode_g
	df['MODE-3A_CODE_L']=mode3acode_l
	df['FLIGHT_LEVEL']=flight_level
	df['FLIGHT_LEVEL_VALIDATION']=flight_level_v
	df['FLIGHT_LEVEL_GARBLE']=flight_level_g

#	df['PACKET']=packet
#	df['BITS']	=bits
	#print(df)
#		f.write(str(count))
#		f.write(',')
#		f.write(str(pkt.header)) 
#		f.write(',')
#		f.write(str(pkt.timestamp))
#		f.write(',')
#		f.write(str(pkt.timestamp_us)) 
#		f.write(',')
#		f.write(str(pkt.capture_len)) 
#		f.write(',')
#		f.write(str(pkt.packet_len)) 
#		f.write(',')
#		f.write(str(pkt.packet)) 
#		f.write('\n')
	
##		print(pkt)
	df.to_csv('{}'.format(csv))
	print('{} contains {} CAT48 packets'.format(file_name, count))
	print('Data and MetaData of packets saved in {}'.format(csv))
	return df

def predict_xy(df):
	df.dropna(inplace=True)
	l=df['MODE-3A_CODE'].unique()
	for i in range(len(l)):
		x=[]
		y=[]
		time=[]
		for j in range(len(df['MODE-3A_CODE'])):
			if l[i]==df['MODE-3A_CODE'].iloc[j] and df['TIME_OF_DAY'].iloc[j]!='':
				x.append(df['X_POLAR_COORDINATE'].iloc[j])
				y.append(df['Y_POLAR_COORDINATE'].iloc[j])
				time.append(df['TIME_OF_DAY'].iloc[j])
		if len(x)>5:
			d=pd.DataFrame()
			d['x']=x
			d['y']=y
			d['t']=time
			#print(d.head())
			d=d.reset_index().sort_values('t',axis=0,ascending=True,na_position='last')
			print('Mode-3/A Code: {}'.format(l[i]))
			print(d.head())
			#for i in range(len(d['t'])-1):
			#	for j in range (len(d['t'])-i):
			#		if d['t'].iloc[j]>d['t'].iloc[j+1]:
			#			buf=d['t'].iloc[j]
			#			d['t'].iloc[j]=d['t'].iloc[j+1]
			#			d['t'].iloc[j+1]=buf
			t_std=d['t'].values.std()
			x_t=np.zeros((8,1))
			x_t[0]=d['t'].iloc[-1]+t_std
			for i in range(1,8):
				x_t[i]=x_t[i-1]+t_std
			lr=LinearRegression()
			lr.fit(d['t'].values.reshape(-1,1),d[['x','y']])
			pred=lr.predict(x_t.reshape(-1,1))
			#p=np.ones((5,2))
			#p*=x_t
			#pred=np.zeros((10,2))
			#for i in range(0,10):
			#	pred[i]=lr.predict(p)[0]
			#	p=np.ones((5,2))
			#	p*=pred[i]

			plt.plot(x,y,c='red')
			plt.plot(pred[:,0],pred[:,1],c='green')
			plt.show()

df=process_pcap(file)
predict_xy(df)

