;`errEvararg_must_be_last
;`errEinvalid_macro_param_name
;`errEvararg_sizeof_nomacro
;`errEmacro_not_varadic
;`errEvararg_out_of_bounds
;`errEvararg_out_of_bounds
;`errEmacro_wrong_min_params
;`errEvararg_out_of_bounds
;`errEmacro_wrong_min_params



lorom
org $008000

!a = 0
macro asd(..., dfg)
	db sizeof(...), <0>, <!a>
endmacro

macro sorry(...)
	db <-1>
endmacro

macro sorry2(asd, ...)
	db <10>
endmacro

macro normal()
	db sizeof(...)
endmacro

macro sorry3(asd, ...)
	db 0
endmacro

%asd(1, 2)
db $FF, $FF
db sizeof(...)
%normal()

%sorry(1,2,3,4,5,6,7)
db $FF, $FF
%sorry2(1,2,3,4,5,6,7)
%sorry2()
%sorry2(0)
%sorry3()

